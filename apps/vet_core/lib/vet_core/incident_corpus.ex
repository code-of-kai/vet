defmodule VetCore.IncidentCorpus do
  @moduledoc """
  Catalog of known supply chain incidents.

  Top rung of the evidence ladder. When a scanned dependency matches an
  entry here — by name, optionally by version, optionally by the shape
  of findings it produced — the matching findings graduate to
  `evidence_level: :known_incident`. That is the strongest signal the
  scanner can produce: "this exact thing was a real compromise."

  The corpus is intentionally small and hand-curated. Noise here is
  worse than gaps — a false `:known_incident` tag is a cry-wolf that
  erodes trust in the whole ladder. Entries should cite a public
  reference (CVE, GHSA, OSV, vendor post-mortem) and describe an
  observable signature, not a general "this package was bad."

  Structure of an entry:

      %{
        ecosystem: :hex,              # currently only :hex is matched
        name: :some_dep,              # dep name (atom)
        version_match: "0.1.0" |      # exact string
                       {:lt, "1.2.3"} |
                       {:range, "1.0.0", "1.5.0"} |
                       :any,
        ref: "GHSA-xxxx-xxxx-xxxx",   # public reference id
        url: "https://...",           # link to report
        summary: "short human sentence",
        # Optional — only promote findings whose category or check_id
        # match. Omit to promote all findings on that dep.
        signature: %{
          categories: [:network_access, :obfuscation],
          check_ids: [:system_exec]
        }
      }

  Lookup is O(entries × deps) — the corpus is expected to stay small
  enough (dozens of entries, not thousands) that a linear scan is fine.
  If it grows past that, index by name.
  """

  alias VetCore.Types.{Dependency, Finding}

  @type version_match ::
          :any
          | String.t()
          | {:lt, String.t()}
          | {:lte, String.t()}
          | {:gte, String.t()}
          | {:range, String.t(), String.t()}

  @type signature :: %{
          optional(:categories) => [atom()],
          optional(:check_ids) => [atom()]
        }

  @type entry :: %{
          required(:ecosystem) => :hex,
          required(:name) => atom(),
          required(:version_match) => version_match(),
          required(:ref) => String.t(),
          required(:url) => String.t(),
          required(:summary) => String.t(),
          optional(:signature) => signature()
        }

  # The corpus. Keep entries ordered by ref alphabetically for easy
  # merging. Each entry MUST cite a public reference — if you can't find
  # one, the incident isn't public enough to include here.
  @corpus [
    # Phantom-package template: an illustrative stub for a typosquat of
    # a popular package. This is a placeholder pattern — real entries
    # should come from verified advisories. Keeping one stub ensures
    # the lookup path is covered by integration tests.
    %{
      ecosystem: :hex,
      name: :phoenx,
      version_match: :any,
      ref: "VET-TYPO-0001",
      url: "https://hex.pm/policies/codeofconduct",
      summary:
        "Typosquat of the popular `phoenix` package name. Any package " <>
          "published under this name should be treated as malicious.",
      signature: %{categories: [:phantom_package]}
    }
  ]

  @doc """
  Return the in-memory corpus. Exposed mainly for tests; callers should
  prefer `match/2` or `promote/2` rather than inspecting entries directly.
  """
  @spec corpus() :: [entry()]
  def corpus, do: @corpus

  @doc """
  Find every corpus entry that matches the given dependency. An entry
  matches when:

    * ecosystems agree (both `:hex` today), and
    * names agree (entry name == dep name), and
    * `version_match` is satisfied by the dep version.

  Returns a list (possibly empty) of matching entries.
  """
  @spec match(Dependency.t()) :: [entry()]
  def match(%Dependency{} = dep) do
    Enum.filter(@corpus, &entry_matches_dep?(&1, dep))
  end

  @doc """
  Promote findings on a dep that matches the corpus.

  For each finding that fits the matched entry's `signature` (or every
  finding if the entry has no signature), returns a new finding with
  `evidence_level: :known_incident`. Findings that don't fit are passed
  through untouched.

  If no corpus entry matches the dep, findings are returned as-is.
  """
  @spec promote(Dependency.t(), [Finding.t()]) :: [Finding.t()]
  def promote(%Dependency{} = dep, findings) when is_list(findings) do
    case match(dep) do
      [] ->
        findings

      matching_entries ->
        Enum.map(findings, fn f ->
          if finding_matches_any?(f, matching_entries) do
            %Finding{f | evidence_level: :known_incident}
          else
            f
          end
        end)
    end
  end

  # --- Matching internals ---------------------------------------------------

  defp entry_matches_dep?(entry, %Dependency{name: name, version: version}) do
    entry.ecosystem == :hex and entry.name == name and
      version_matches?(entry.version_match, version)
  end

  defp version_matches?(:any, _), do: true
  defp version_matches?(_, nil), do: false

  defp version_matches?(expected, actual) when is_binary(expected) and is_binary(actual) do
    expected == actual
  end

  defp version_matches?({:lt, limit}, actual) when is_binary(actual) do
    compare(actual, limit) == :lt
  end

  defp version_matches?({:lte, limit}, actual) when is_binary(actual) do
    compare(actual, limit) in [:lt, :eq]
  end

  defp version_matches?({:gte, limit}, actual) when is_binary(actual) do
    compare(actual, limit) in [:gt, :eq]
  end

  defp version_matches?({:range, lo, hi}, actual) when is_binary(actual) do
    compare(actual, lo) in [:gt, :eq] and compare(actual, hi) in [:lt, :eq]
  end

  defp version_matches?(_, _), do: false

  defp compare(a, b) do
    with {:ok, av} <- Version.parse(a),
         {:ok, bv} <- Version.parse(b) do
      Version.compare(av, bv)
    else
      _ -> :invalid
    end
  end

  defp finding_matches_any?(finding, entries) do
    Enum.any?(entries, &signature_matches?(&1, finding))
  end

  defp signature_matches?(entry, finding) do
    case Map.get(entry, :signature) do
      nil ->
        true

      %{} = sig ->
        cat_ok =
          case Map.get(sig, :categories) do
            nil -> true
            cats -> finding.category in cats
          end

        id_ok =
          case Map.get(sig, :check_ids) do
            nil -> true
            ids -> finding.check_id in ids
          end

        cat_ok and id_ok
    end
  end
end
