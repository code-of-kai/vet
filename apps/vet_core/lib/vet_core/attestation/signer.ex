defmodule VetCore.Attestation.Signer do
  @moduledoc """
  Ed25519 signing for attestation manifests.

  Built on `:public_key` and `:crypto` from OTP — no third-party crypto
  libraries. Ed25519 was chosen because:

  - It's a deterministic signature scheme: same key + same message =
    same signature. Replay-detectable.
  - Public keys are 32 bytes, signatures are 64 bytes. Cheap to embed.
  - Signature verification is constant-time, no patent issues.

  Keys are stored as `%{public: <32 bytes>, private: <32 bytes>}` and
  serialized to PEM-style text via `encode_key/2` for storage on disk.
  """

  @doc """
  Generate a fresh Ed25519 keypair.
  """
  @spec generate_keypair() :: %{public: binary(), private: binary()}
  def generate_keypair do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    %{public: pub, private: priv}
  end

  @doc """
  Sign a binary message with an Ed25519 private key. Returns the
  64-byte signature.
  """
  @spec sign(binary(), binary()) :: binary()
  def sign(message, private_key) when is_binary(message) and is_binary(private_key) do
    :crypto.sign(:eddsa, :sha512, message, [private_key, :ed25519])
  end

  @doc """
  Sign a manifest. Returns `{manifest_json, signature_bytes}` — the
  caller writes both to a `.manifest.json` and `.sig` file pair.
  """
  @spec sign_manifest(VetCore.Attestation.Manifest.t(), binary()) :: {String.t(), binary()}
  def sign_manifest(manifest, private_key) do
    json = VetCore.Attestation.Manifest.to_canonical_json(manifest)
    sig = sign(json, private_key)
    {json, sig}
  end

  @doc """
  Encode a key as base64url for portability. Use `:public` for public
  keys and `:private` for private keys.
  """
  @spec encode_key(binary(), :public | :private) :: String.t()
  def encode_key(bytes, kind) when kind in [:public, :private] and is_binary(bytes) do
    prefix =
      case kind do
        :public -> "ed25519-pub:"
        :private -> "ed25519-sec:"
      end

    prefix <> Base.url_encode64(bytes, padding: false)
  end

  @doc """
  Decode a `ed25519-pub:` or `ed25519-sec:` encoded key back to bytes.
  Returns `{:ok, bytes}` or `{:error, reason}`.
  """
  @spec decode_key(String.t()) :: {:ok, binary()} | {:error, term()}
  def decode_key("ed25519-pub:" <> b64), do: do_decode(b64)
  def decode_key("ed25519-sec:" <> b64), do: do_decode(b64)
  def decode_key(_), do: {:error, :unknown_key_format}

  defp do_decode(b64) do
    case Base.url_decode64(b64, padding: false) do
      {:ok, bytes} when byte_size(bytes) == 32 -> {:ok, bytes}
      {:ok, _} -> {:error, :wrong_key_size}
      :error -> {:error, :invalid_base64}
    end
  end
end
