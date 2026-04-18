defmodule VetCore.Attestation.Manifest do
  @moduledoc """
  Signed claim about a package: "version X of package P has BEAM content
  hashes H₁ … Hₙ, capability set C, and was reviewed by signer S at
  time T."

  Encoded as canonical JSON for signing. Signing/verification uses
  Ed25519 (`VetCore.Attestation.Signer` / `VetCore.Attestation.Verifier`).

  Trust model: signatures bind a manifest to a public key. The public
  key's reputation is out-of-band — Vet doesn't decide which keys to
  trust, the user does (configurable trust roots in
  `~/.vet/trusted_keys/` or per-project allowlists).

  Manifests can be registered with `VetService` for sharing across an
  organization or community.
  """

  defstruct [
    :package,
    :version,
    :module_hashes,
    :capabilities,
    :signer,
    :signed_at,
    :notes
  ]

  @type module_hash :: %{module: String.t(), content_hash: String.t()}

  @type t :: %__MODULE__{
          package: String.t(),
          version: String.t(),
          module_hashes: [module_hash()],
          capabilities: [atom()],
          signer: String.t(),
          signed_at: String.t(),
          notes: String.t() | nil
        }

  @doc """
  Build a manifest from a list of `BeamProfile` snapshots and a
  capability set. The signed_at timestamp is set to now.
  """
  @spec build(String.t(), String.t(), [VetCore.BEAM.BeamProfile.t()], [atom()], String.t(), keyword()) ::
          t()
  def build(package, version, profiles, capabilities, signer, opts \\ []) do
    %__MODULE__{
      package: package,
      version: version,
      module_hashes:
        Enum.map(profiles, fn profile ->
          %{
            module: to_string(profile.module),
            content_hash: VetCore.BEAM.BeamProfile.content_hash(profile)
          }
        end)
        |> Enum.sort_by(& &1.module),
      capabilities: Enum.sort(capabilities),
      signer: signer,
      signed_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      notes: Keyword.get(opts, :notes)
    }
  end

  @doc """
  Encode a manifest to canonical JSON for signing. Keys are sorted to
  guarantee deterministic byte output regardless of map ordering, which
  matters because the signature is over the bytes.
  """
  @spec to_canonical_json(t()) :: String.t()
  def to_canonical_json(%__MODULE__{} = m) do
    %{
      "package" => m.package,
      "version" => m.version,
      "module_hashes" => Enum.map(m.module_hashes, &normalize_hash/1),
      "capabilities" => Enum.map(m.capabilities, &Atom.to_string/1) |> Enum.sort(),
      "signer" => m.signer,
      "signed_at" => m.signed_at,
      "notes" => m.notes
    }
    |> sort_deep()
    |> Jason.encode!()
  end

  defp normalize_hash(%{module: m, content_hash: h}) do
    %{"module" => to_string(m), "content_hash" => h}
  end

  # Recursively sort map keys so Jason.encode! produces deterministic
  # byte output. OrderedObject preserves iteration order; sorting the
  # entries first means equal inputs yield equal bytes.
  defp sort_deep(value) when is_map(value) do
    value
    |> Enum.map(fn {k, v} -> {to_string(k), sort_deep(v)} end)
    |> Enum.sort_by(fn {k, _} -> k end)
    |> Jason.OrderedObject.new()
  end

  defp sort_deep(value) when is_list(value), do: Enum.map(value, &sort_deep/1)
  defp sort_deep(value), do: value

  @doc """
  Decode a manifest from JSON.
  """
  @spec from_json(String.t()) :: {:ok, t()} | {:error, term()}
  def from_json(json) when is_binary(json) do
    with {:ok, map} <- Jason.decode(json),
         %{} <- map do
      capabilities =
        map
        |> Map.get("capabilities", [])
        |> Enum.map(&safe_atom/1)
        |> Enum.reject(&is_nil/1)

      module_hashes =
        map
        |> Map.get("module_hashes", [])
        |> Enum.map(fn %{"module" => m, "content_hash" => h} ->
          %{module: m, content_hash: h}
        end)

      {:ok,
       %__MODULE__{
         package: Map.get(map, "package"),
         version: Map.get(map, "version"),
         module_hashes: module_hashes,
         capabilities: capabilities,
         signer: Map.get(map, "signer"),
         signed_at: Map.get(map, "signed_at"),
         notes: Map.get(map, "notes")
       }}
    else
      _ -> {:error, :invalid_manifest}
    end
  end

  defp safe_atom(s) when is_binary(s) do
    String.to_existing_atom(s)
  rescue
    ArgumentError -> nil
  end

  defp safe_atom(_), do: nil
end
