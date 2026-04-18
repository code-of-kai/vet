defmodule VetCore.LLMReview do
  @moduledoc """
  Integrates LLM analysis for deep code review of flagged dependencies.

  Uses the Anthropic API to provide AI-powered security assessment
  beyond what deterministic scanning can catch.
  """

  alias VetCore.Types.{DependencyReport, ScanReport, Finding}
  alias VetCore.Checks.FileHelper

  @default_model "claude-sonnet-4-20250514"
  @api_url "https://api.anthropic.com/v1/messages"

  @type review_result :: %{
          ai_analysis: String.t(),
          model: String.t(),
          reviewed_at: DateTime.t()
        }

  @doc """
  Reviews a single dependency report using LLM analysis.

  ## Options

    * `:api_key` - Anthropic API key (required, or set ANTHROPIC_API_KEY env var)
    * `:model` - Model to use (default: #{@default_model})
    * `:max_tokens` - Max response tokens (default: 4096)
    * `:project_path` - Path to project root (needed to read source files)

  """
  @spec review(DependencyReport.t(), keyword()) :: {:ok, review_result()} | {:error, term()}
  def review(%DependencyReport{} = dep_report, opts \\ []) do
    api_key = opts[:api_key] || System.get_env("ANTHROPIC_API_KEY")

    if is_nil(api_key) or api_key == "" do
      {:error, :missing_api_key}
    else
      model = opts[:model] || @default_model
      max_tokens = opts[:max_tokens] || 4096
      project_path = opts[:project_path]

      prompt = format_prompt(dep_report, project_path)

      case call_api(api_key, model, prompt, max_tokens) do
        {:ok, response_text} ->
          {:ok,
           %{
             ai_analysis: response_text,
             model: model,
             reviewed_at: DateTime.utc_now()
           }}

        {:error, _} = err ->
          err
      end
    end
  end

  @doc """
  Reviews only dependencies in the scan report that have a risk score above
  the given threshold.

  ## Options

  Same as `review/2`, plus:

    * `:threshold` - Minimum risk score to trigger review (default: 50)

  """
  @spec review_flagged(ScanReport.t(), keyword()) ::
          {:ok, [{atom(), review_result()}]} | {:error, term()}
  def review_flagged(%ScanReport{} = scan_report, opts \\ []) do
    threshold = opts[:threshold] || 50

    flagged =
      scan_report.dependency_reports
      |> Enum.filter(fn dr -> dr.risk_score >= threshold end)

    results =
      Enum.map(flagged, fn dr ->
        case review(dr, Keyword.put(opts, :project_path, scan_report.project_path)) do
          {:ok, result} -> {dr.dependency.name, {:ok, result}}
          {:error, reason} -> {dr.dependency.name, {:error, reason}}
        end
      end)

    {:ok, results}
  end

  @doc """
  Builds a well-structured prompt for LLM security review.

  Public for testing.
  """
  @spec format_prompt(DependencyReport.t(), String.t() | nil) :: String.t()
  def format_prompt(%DependencyReport{} = dep_report, project_path \\ nil) do
    dep = dep_report.dependency
    findings = dep_report.findings

    source_snippets = build_source_snippets(dep, findings, project_path)

    """
    You are a security researcher reviewing an Elixir dependency for supply chain attack indicators.

    Package: #{dep.name} v#{dep.version || "unknown"}
    Source: #{format_source(dep.source)}

    Deterministic scan findings:
    #{format_findings(findings)}

    Source code of flagged files:
    #{source_snippets}

    Questions:
    1. Are any of these findings likely false positives? Why?
    2. Are there additional security concerns not caught by the deterministic scan?
    3. What is your overall risk assessment (low/medium/high/critical)?
    4. Recommended actions?
    """
  end

  # ---------------------------------------------------------------------------
  # Adversarial verification
  #
  # Clearwing's insight: a single LLM pass is an accusation. Adversarial
  # verification runs a second "devil's advocate" agent that tries to argue
  # the code is benign, then a judge synthesizes both. Confirmed findings
  # get promoted to :llm_confirmed; refuted findings get downgraded.
  # ---------------------------------------------------------------------------

  @doc """
  Builds a devil's-advocate prompt — the refutation agent's job is to argue
  each finding is a legitimate library pattern, citing common idioms.

  Public for testing.
  """
  @spec format_refutation_prompt(DependencyReport.t(), String.t() | nil) :: String.t()
  def format_refutation_prompt(%DependencyReport{} = dep_report, project_path \\ nil) do
    dep = dep_report.dependency
    findings = dep_report.findings
    source_snippets = build_source_snippets(dep, findings, project_path)

    """
    You are a defense attorney for an Elixir library accused of being malicious.
    Your job is to argue — for each flagged finding — that it is a legitimate
    library pattern, not a supply-chain attack. Steelman the defense. Cite
    common idioms (CLI wrappers, build scripts, config loaders, HTTP clients,
    template engines) when they apply.

    Package: #{dep.name} v#{dep.version || "unknown"}
    Source: #{format_source(dep.source)}

    Accusations (deterministic scan findings):
    #{format_findings(findings)}

    Source code of flagged files:
    #{source_snippets}

    For EACH finding above, respond with exactly this format on its own line:
      FINDING #<index>: REFUTED — <one-sentence legitimate explanation>
    OR
      FINDING #<index>: CONCEDED — <one-sentence why defense fails>

    Then a one-paragraph summary of your strongest defense.
    """
  end

  @doc """
  Builds the judge prompt. The judge sees the original accusation AND the
  refutation, and renders a verdict per finding.

  Public for testing.
  """
  @spec format_judge_prompt(DependencyReport.t(), String.t(), String.t()) :: String.t()
  def format_judge_prompt(%DependencyReport{} = dep_report, accusation, refutation) do
    """
    You are an impartial judge reviewing a security dispute over an Elixir
    dependency. The prosecution (deterministic scanner + security analyst)
    alleges malicious patterns. The defense argues these are legitimate.

    Your verdict must be conservative: do NOT confirm malice unless the
    accusation's evidence clearly outweighs the defense's explanation.
    Uncertainty should resolve as REFUTED, not CONFIRMED.

    Package: #{dep_report.dependency.name} v#{dep_report.dependency.version || "unknown"}

    Accusations (per-finding):
    #{format_findings(dep_report.findings)}

    Prosecution analysis:
    #{accusation}

    Defense argument:
    #{refutation}

    For EACH finding, respond with exactly this format on its own line:
      FINDING #<index>: CONFIRMED — <one-sentence reason>
    OR
      FINDING #<index>: REFUTED — <one-sentence reason>
    OR
      FINDING #<index>: UNCERTAIN — <one-sentence reason>

    Then a one-line overall verdict:
      OVERALL: MALICIOUS | BENIGN | UNCERTAIN
    """
  end

  @typedoc "Per-finding verdict from the judge."
  @type verdict :: :confirmed | :refuted | :uncertain

  @typedoc "Overall verdict for the dep."
  @type overall_verdict :: :malicious | :benign | :uncertain

  @typedoc """
  Parsed judge response — an overall verdict plus a map from 1-indexed finding
  position to per-finding verdict.
  """
  @type judgment :: %{
          overall: overall_verdict(),
          per_finding: %{pos_integer() => verdict()}
        }

  @doc """
  Parses the judge's text response into a structured verdict.

  The parser is conservative: malformed or missing per-finding lines default
  to `:uncertain`. Public for testing (and so the scanner can reuse it when
  an offline/cached judgment is supplied).
  """
  @spec parse_judgment(String.t(), non_neg_integer()) :: judgment()
  def parse_judgment(text, finding_count) when is_binary(text) do
    lines = String.split(text, "\n")

    per_finding =
      for {line, _idx} <- Enum.with_index(lines),
          captured = Regex.run(~r/FINDING\s+#(\d+):\s*(CONFIRMED|REFUTED|UNCERTAIN)/i, line),
          captured != nil,
          into: %{} do
        [_, num_s, verdict_s] = captured
        {String.to_integer(num_s), parse_verdict_token(verdict_s)}
      end

    # Fill in any missing findings as :uncertain to keep downstream logic total.
    per_finding =
      Enum.reduce(1..max(finding_count, 0)//1, per_finding, fn i, acc ->
        Map.put_new(acc, i, :uncertain)
      end)

    overall =
      case Regex.run(~r/OVERALL:\s*(MALICIOUS|BENIGN|UNCERTAIN)/i, text) do
        [_, token] -> parse_overall_token(token)
        _ -> :uncertain
      end

    %{overall: overall, per_finding: per_finding}
  end

  defp parse_verdict_token(s) do
    case String.upcase(s) do
      "CONFIRMED" -> :confirmed
      "REFUTED" -> :refuted
      _ -> :uncertain
    end
  end

  defp parse_overall_token(s) do
    case String.upcase(s) do
      "MALICIOUS" -> :malicious
      "BENIGN" -> :benign
      _ -> :uncertain
    end
  end

  @doc """
  Given the original findings and a parsed judgment, returns a new finding
  list where `:confirmed` findings are promoted to `evidence_level:
  :llm_confirmed` and `:refuted` findings are demoted one severity tier.
  `:uncertain` findings are left unchanged.

  Severity demotion: critical → warning → info; info stays info. This is how
  the adversarial pass actually reduces false-positive noise without
  discarding the finding entirely.
  """
  @spec apply_judgment([Finding.t()], judgment()) :: [Finding.t()]
  def apply_judgment(findings, %{per_finding: per_finding}) do
    findings
    |> Enum.with_index(1)
    |> Enum.map(fn {finding, idx} ->
      case Map.get(per_finding, idx, :uncertain) do
        :confirmed ->
          %{finding | evidence_level: :llm_confirmed}

        :refuted ->
          %{finding | severity: demote_severity(finding.severity)}

        :uncertain ->
          finding
      end
    end)
  end

  defp demote_severity(:critical), do: :warning
  defp demote_severity(:warning), do: :info
  defp demote_severity(:info), do: :info

  @doc """
  Runs the full adversarial pipeline for a dependency: accusation → refutation
  → judge → apply_judgment. Returns `{:ok, %{findings, judgment, accusation,
  refutation}}` or an error tuple if any API call fails.

  When the Anthropic API key is not available, the function returns
  `{:error, :missing_api_key}` without mutating findings. The caller is
  responsible for choosing whether to invoke this pipeline (gated in the
  scanner by the `adversarial: true` option).
  """
  @spec review_with_refutation(DependencyReport.t(), keyword()) ::
          {:ok,
           %{
             findings: [Finding.t()],
             judgment: judgment(),
             accusation: String.t(),
             refutation: String.t()
           }}
          | {:error, term()}
  def review_with_refutation(%DependencyReport{findings: []} = _dep_report, _opts) do
    # No findings to adjudicate — pipeline is a no-op.
    {:ok,
     %{
       findings: [],
       judgment: %{overall: :benign, per_finding: %{}},
       accusation: "",
       refutation: ""
     }}
  end

  def review_with_refutation(%DependencyReport{} = dep_report, opts) do
    api_key = opts[:api_key] || System.get_env("ANTHROPIC_API_KEY")

    if is_nil(api_key) or api_key == "" do
      {:error, :missing_api_key}
    else
      model = opts[:model] || @default_model
      max_tokens = opts[:max_tokens] || 2048
      project_path = opts[:project_path]

      accusation_prompt = format_prompt(dep_report, project_path)
      refutation_prompt = format_refutation_prompt(dep_report, project_path)

      with {:ok, accusation} <- call_api(api_key, model, accusation_prompt, max_tokens),
           {:ok, refutation} <- call_api(api_key, model, refutation_prompt, max_tokens),
           judge_prompt = format_judge_prompt(dep_report, accusation, refutation),
           {:ok, judge_text} <- call_api(api_key, model, judge_prompt, max_tokens) do
        judgment = parse_judgment(judge_text, length(dep_report.findings))
        updated_findings = apply_judgment(dep_report.findings, judgment)

        {:ok,
         %{
           findings: updated_findings,
           judgment: judgment,
           accusation: accusation,
           refutation: refutation
         }}
      end
    end
  end

  # -- Private: API ------------------------------------------------------------

  defp call_api(api_key, _model, prompt, _max_tokens) do
    case Req.post(
           @api_url,
           headers: [
             {"x-api-key", api_key},
             {"anthropic-version", "2023-06-01"},
             {"content-type", "application/json"}
           ],
           json: %{
             model: "claude-sonnet-4-20250514",
             max_tokens: 2048,
             messages: [%{role: "user", content: prompt}]
           }
         ) do
      {:ok, %{status: 200, body: body}} ->
        parse_response(body)

      {:ok, %{status: 429}} ->
        {:error, :rate_limited}

      {:ok, %{status: status, body: body}} ->
        {:error, "API error #{status}: #{inspect(body)}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  defp parse_response(%{"content" => [%{"text" => text} | _]}), do: {:ok, text}
  defp parse_response(%{"error" => %{"message" => msg}}), do: {:error, {:api_error, msg}}
  defp parse_response(other), do: {:error, {:unexpected_response, other}}

  # -- Private: Prompt building ------------------------------------------------

  defp format_source(:hex), do: "hex.pm"
  defp format_source({:git, url}), do: "git: #{url}"
  defp format_source({:path, path}), do: "path: #{path}"
  defp format_source(nil), do: "unknown"
  defp format_source(other), do: inspect(other)

  defp format_findings([]), do: "  (none)"

  defp format_findings(findings) do
    findings
    |> Enum.with_index(1)
    |> Enum.map_join("\n", fn {%Finding{} = f, idx} ->
      ct = if f.compile_time?, do: " [COMPILE-TIME]", else: ""
      "  #{idx}. [#{f.severity}#{ct}] #{f.description}\n     File: #{shorten_path(f.file_path)}:#{f.line}"
    end)
  end

  defp build_source_snippets(_dep, _findings, nil), do: "  (source not available)"

  defp build_source_snippets(dep, findings, project_path) do
    flagged_files =
      findings
      |> Enum.map(& &1.file_path)
      |> Enum.uniq()

    if flagged_files == [] do
      "  (no flagged files)"
    else
      parsed_files = FileHelper.read_and_parse(dep.name, project_path)

      parsed_files
      |> Enum.filter(fn {path, _source, _ast} -> path in flagged_files end)
      |> Enum.map_join("\n\n", fn {path, source, _ast} ->
        truncated =
          source
          |> String.split("\n")
          |> Enum.take(200)
          |> Enum.join("\n")

        "--- #{shorten_path(path)} ---\n#{truncated}"
      end)
      |> case do
        "" -> "  (flagged files not readable)"
        content -> content
      end
    end
  end

  defp shorten_path(path) do
    case String.split(path, "/deps/") do
      [_, rest] -> "deps/" <> rest
      _ -> path
    end
  end
end
