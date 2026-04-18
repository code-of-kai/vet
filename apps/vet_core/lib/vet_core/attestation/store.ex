defmodule VetCore.Attestation.Store do
  @moduledoc """
  Local store for attestation manifests and trusted public keys.

  Layout:

      <project>/.vet/attestations/
        <package>/<version>.manifest.json
        <package>/<version>.sig

      ~/.vet/trusted_keys/
        <name>.pub      # ed25519-pub:... format

  Trusted keys can also live in `<project>/.vet/trusted_keys/` for
  per-project policy that overrides global trust.
  """

  alias VetCore.Attestation.{Manifest, Signer}

  @attestation_dir ".vet/attestations"
  @project_keys_dir ".vet/trusted_keys"
  @global_keys_dir "~/.vet/trusted_keys"

  @doc """
  Save a `{manifest, signature}` pair to the local attestation store.
  """
  @spec save(String.t(), Manifest.t(), binary()) :: :ok
  def save(project_path, %Manifest{} = manifest, signature) when is_binary(signature) do
    dir = Path.join([project_path, @attestation_dir, manifest.package])
    File.mkdir_p!(dir)

    manifest_path = Path.join(dir, "#{manifest.version}.manifest.json")
    sig_path = Path.join(dir, "#{manifest.version}.sig")

    File.write!(manifest_path, Manifest.to_canonical_json(manifest))
    File.write!(sig_path, signature)

    :ok
  end

  @doc """
  Load a stored attestation pair for a `{package, version}`. Returns
  `{:ok, {manifest, signature}}` or `{:error, reason}`.
  """
  @spec load(String.t(), String.t(), String.t()) ::
          {:ok, {Manifest.t(), binary()}} | {:error, term()}
  def load(project_path, package, version) do
    dir = Path.join([project_path, @attestation_dir, package])
    manifest_path = Path.join(dir, "#{version}.manifest.json")
    sig_path = Path.join(dir, "#{version}.sig")

    with {:ok, json} <- File.read(manifest_path),
         {:ok, sig} <- File.read(sig_path),
         {:ok, manifest} <- Manifest.from_json(json) do
      {:ok, {manifest, sig}}
    else
      _ -> {:error, :no_attestation}
    end
  end

  @doc """
  Load every trusted public key from the project-local and global
  trusted-keys directories. Returns a list of `{name, key_bytes}`.
  """
  @spec trusted_keys(String.t()) :: [{String.t(), binary()}]
  def trusted_keys(project_path) do
    project_dir = Path.join(project_path, @project_keys_dir)
    global_dir = Path.expand(@global_keys_dir)

    load_keys_from(project_dir) ++ load_keys_from(global_dir)
  end

  defp load_keys_from(dir) do
    case File.ls(dir) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".pub"))
        |> Enum.flat_map(fn name ->
          full = Path.join(dir, name)

          with {:ok, encoded} <- File.read(full),
               {:ok, bytes} <- Signer.decode_key(String.trim(encoded)) do
            [{Path.rootname(name), bytes}]
          else
            _ -> []
          end
        end)

      {:error, _} ->
        []
    end
  end
end
