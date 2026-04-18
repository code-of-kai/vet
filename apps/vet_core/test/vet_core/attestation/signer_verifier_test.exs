defmodule VetCore.Attestation.SignerVerifierTest do
  use ExUnit.Case, async: true

  alias VetCore.Attestation.{Manifest, Signer, Verifier}
  alias VetCore.BEAM.BeamProfile

  describe "generate_keypair/0" do
    test "returns 32-byte public and private keys" do
      %{public: pub, private: priv} = Signer.generate_keypair()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "each call produces a fresh keypair" do
      %{public: pub1} = Signer.generate_keypair()
      %{public: pub2} = Signer.generate_keypair()
      refute pub1 == pub2
    end
  end

  describe "sign/2 and verify/3" do
    test "a fresh signature verifies with the matching public key" do
      %{public: pub, private: priv} = Signer.generate_keypair()
      message = "hello world"
      sig = Signer.sign(message, priv)

      assert byte_size(sig) == 64
      assert :ok = Verifier.verify(message, sig, pub)
    end

    test "verification fails with a different public key" do
      %{private: priv} = Signer.generate_keypair()
      %{public: other_pub} = Signer.generate_keypair()

      sig = Signer.sign("msg", priv)
      assert {:error, :bad_signature} = Verifier.verify("msg", sig, other_pub)
    end

    test "verification fails if the message has been tampered with" do
      %{public: pub, private: priv} = Signer.generate_keypair()
      sig = Signer.sign("original", priv)
      assert {:error, :bad_signature} = Verifier.verify("tampered", sig, pub)
    end

    test "verify/3 rejects wrongly-sized keys and signatures" do
      %{public: pub, private: priv} = Signer.generate_keypair()
      sig = Signer.sign("m", priv)

      assert {:error, :wrong_input_size} = Verifier.verify("m", sig, <<0, 1, 2>>)
      assert {:error, :wrong_input_size} = Verifier.verify("m", <<0, 1, 2>>, pub)
    end
  end

  describe "encode_key/2 and decode_key/1" do
    test "round-trips a public key" do
      %{public: pub} = Signer.generate_keypair()
      encoded = Signer.encode_key(pub, :public)
      assert String.starts_with?(encoded, "ed25519-pub:")
      assert {:ok, ^pub} = Signer.decode_key(encoded)
    end

    test "round-trips a private key" do
      %{private: priv} = Signer.generate_keypair()
      encoded = Signer.encode_key(priv, :private)
      assert String.starts_with?(encoded, "ed25519-sec:")
      assert {:ok, ^priv} = Signer.decode_key(encoded)
    end

    test "decode rejects unknown prefixes" do
      assert {:error, :unknown_key_format} = Signer.decode_key("rsa-pub:abc")
      assert {:error, :unknown_key_format} = Signer.decode_key("garbage")
    end

    test "decode rejects malformed base64" do
      assert {:error, :invalid_base64} = Signer.decode_key("ed25519-pub:!!!not-base64!!!")
    end

    test "decode rejects wrong-sized keys" do
      # 4 bytes of base64url = 3 raw bytes, which is not 32.
      short = Base.url_encode64(<<1, 2, 3>>, padding: false)
      assert {:error, :wrong_key_size} = Signer.decode_key("ed25519-pub:" <> short)
    end
  end

  describe "sign_manifest/2" do
    test "produces a json+signature pair that verifies against the signed canonical form" do
      profile = %BeamProfile{
        module: Foo,
        imports: [],
        exports: [],
        atoms: [],
        attributes: %{},
        compile_info: %{},
        dynamic_dispatch_count: 0
      }

      %{public: pub, private: priv} = Signer.generate_keypair()
      manifest = Manifest.build("pkg", "1.0.0", [profile], [:network], "alice")

      {json, sig} = Signer.sign_manifest(manifest, priv)

      assert json == Manifest.to_canonical_json(manifest)
      assert :ok = Verifier.verify(json, sig, pub)
    end
  end

  describe "verify_against_install/2" do
    test "returns :ok when every manifest hash matches a local profile" do
      profile = %BeamProfile{
        module: Foo,
        imports: [],
        exports: [],
        atoms: [],
        attributes: %{}
      }

      manifest = %Manifest{
        package: "p",
        version: "1",
        module_hashes: [%{module: "Elixir.Foo", content_hash: BeamProfile.content_hash(profile)}],
        capabilities: [],
        signer: "s",
        signed_at: "t"
      }

      assert :ok = Verifier.verify_against_install(manifest, [profile])
    end

    test "flags hash mismatch when the local module has been tampered with" do
      local_profile = %BeamProfile{
        module: Foo,
        imports: [{:os, :cmd, 1}],
        exports: [],
        atoms: [],
        attributes: %{}
      }

      manifest = %Manifest{
        package: "p",
        version: "1",
        module_hashes: [%{module: "Elixir.Foo", content_hash: "declared-hash-bytes-from-signing-time"}],
        capabilities: [],
        signer: "s",
        signed_at: "t"
      }

      assert {:error, {:hash_mismatch, [diff]}} =
               Verifier.verify_against_install(manifest, [local_profile])

      assert diff.module == "Elixir.Foo"
      assert diff.status == :hash_mismatch
      assert diff.declared == "declared-hash-bytes-from-signing-time"
      assert diff.local == BeamProfile.content_hash(local_profile)
    end

    test "flags missing modules — manifest declares something not installed locally" do
      manifest = %Manifest{
        package: "p",
        version: "1",
        module_hashes: [%{module: "Elixir.GhostModule", content_hash: "x"}],
        capabilities: [],
        signer: "s",
        signed_at: "t"
      }

      assert {:error, {:hash_mismatch, [diff]}} = Verifier.verify_against_install(manifest, [])
      assert diff.status == :missing_locally
      assert diff.module == "Elixir.GhostModule"
      assert diff.local == nil
    end
  end
end
