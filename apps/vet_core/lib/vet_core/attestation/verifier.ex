defmodule VetCore.Attestation.Verifier do
  @moduledoc """
  Verify Ed25519-signed attestation manifests.

  Two surfaces:

  - `verify/3` — pure crypto check. Given a manifest JSON, signature,
    and public key, returns `:ok` or `{:error, reason}`.
  - `verify_against_install/3` — domain check. Given a manifest and a
    list of locally-observed `BeamProfile`s, ensure every module hash
    declared in the manifest matches the local install.

  Combined, these answer: "did the signer attest to *exactly* the bytes
  I have on disk?"
  """

  alias VetCore.Attestation.Manifest
  alias VetCore.BEAM.BeamProfile

  @doc """
  Verify an Ed25519 signature over a manifest JSON blob.
  """
  @spec verify(String.t(), binary(), binary()) :: :ok | {:error, term()}
  def verify(manifest_json, signature, public_key)
      when is_binary(manifest_json) and is_binary(signature) and is_binary(public_key) do
    if byte_size(public_key) == 32 and byte_size(signature) == 64 do
      case :crypto.verify(:eddsa, :sha512, manifest_json, signature, [public_key, :ed25519]) do
        true -> :ok
        false -> {:error, :bad_signature}
      end
    else
      {:error, :wrong_input_size}
    end
  end

  @doc """
  Compare a manifest's `module_hashes` against a list of locally-loaded
  `BeamProfile`s. Returns `:ok` if every module declared in the
  manifest is present locally with the same content_hash. Returns
  `{:error, {:hash_mismatch, [diff_entry]}}` listing modules that
  differ or are missing.
  """
  @spec verify_against_install(Manifest.t(), [BeamProfile.t()]) ::
          :ok | {:error, term()}
  def verify_against_install(%Manifest{module_hashes: declared}, profiles) when is_list(declared) do
    local =
      profiles
      |> Map.new(fn profile ->
        {to_string(profile.module), BeamProfile.content_hash(profile)}
      end)

    diffs =
      Enum.flat_map(declared, fn %{module: m, content_hash: declared_hash} ->
        case Map.get(local, m) do
          nil -> [%{module: m, status: :missing_locally, declared: declared_hash, local: nil}]
          ^declared_hash -> []
          local_hash -> [%{module: m, status: :hash_mismatch, declared: declared_hash, local: local_hash}]
        end
      end)

    if diffs == [], do: :ok, else: {:error, {:hash_mismatch, diffs}}
  end
end
