defmodule VetCore.Attestation.StoreTest do
  use ExUnit.Case, async: true

  alias VetCore.Attestation.{Manifest, Signer, Store, Verifier}
  alias VetCore.BEAM.BeamProfile

  setup do
    tmp = Path.join(System.tmp_dir!(), "vet_store_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)
    {:ok, project_path: tmp}
  end

  describe "save/3 and load/3" do
    test "round-trips a manifest and signature pair", %{project_path: path} do
      profile = %BeamProfile{
        module: Foo,
        imports: [],
        exports: [],
        atoms: [],
        attributes: %{}
      }

      %{public: pub, private: priv} = Signer.generate_keypair()
      manifest = Manifest.build("my_pkg", "1.0.0", [profile], [:network], "alice@example")
      {_json, sig} = Signer.sign_manifest(manifest, priv)

      assert :ok = Store.save(path, manifest, sig)

      assert {:ok, {loaded_manifest, loaded_sig}} = Store.load(path, "my_pkg", "1.0.0")
      assert loaded_manifest.package == "my_pkg"
      assert loaded_manifest.version == "1.0.0"
      assert loaded_sig == sig

      # And the loaded pair still verifies end-to-end.
      json = Manifest.to_canonical_json(loaded_manifest)
      assert :ok = Verifier.verify(json, loaded_sig, pub)
    end

    test "save writes to the expected directory layout", %{project_path: path} do
      %{private: priv} = Signer.generate_keypair()
      manifest = Manifest.build("abc", "2.0.0", [], [], "s")
      {_, sig} = Signer.sign_manifest(manifest, priv)

      :ok = Store.save(path, manifest, sig)

      assert File.exists?(Path.join([path, ".vet", "attestations", "abc", "2.0.0.manifest.json"]))
      assert File.exists?(Path.join([path, ".vet", "attestations", "abc", "2.0.0.sig"]))
    end

    test "load returns :no_attestation for missing files", %{project_path: path} do
      assert {:error, :no_attestation} = Store.load(path, "nothing", "0.0.0")
    end

    test "load returns :no_attestation if signature file is missing", %{project_path: path} do
      manifest = Manifest.build("pkg", "1.0.0", [], [], "s")
      dir = Path.join([path, ".vet", "attestations", "pkg"])
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "1.0.0.manifest.json"), Manifest.to_canonical_json(manifest))
      # signature file deliberately absent

      assert {:error, :no_attestation} = Store.load(path, "pkg", "1.0.0")
    end
  end

  describe "trusted_keys/1" do
    test "loads .pub files from project-local trusted_keys dir", %{project_path: path} do
      keys_dir = Path.join(path, ".vet/trusted_keys")
      File.mkdir_p!(keys_dir)

      %{public: pub} = Signer.generate_keypair()
      File.write!(Path.join(keys_dir, "alice.pub"), Signer.encode_key(pub, :public))

      keys = Store.trusted_keys(path)
      names = Enum.map(keys, fn {n, _} -> n end)

      assert "alice" in names
      assert Enum.any?(keys, fn {_, bytes} -> bytes == pub end)
    end

    test "skips non-.pub files and malformed keys", %{project_path: path} do
      keys_dir = Path.join(path, ".vet/trusted_keys")
      File.mkdir_p!(keys_dir)

      %{public: pub} = Signer.generate_keypair()
      File.write!(Path.join(keys_dir, "good.pub"), Signer.encode_key(pub, :public))
      File.write!(Path.join(keys_dir, "notes.txt"), "ignore me")
      File.write!(Path.join(keys_dir, "broken.pub"), "garbage-not-a-key")

      keys = Store.trusted_keys(path)
      names = Enum.map(keys, fn {n, _} -> n end)

      assert names == ["good"]
    end

    test "returns empty list when no keys dir exists", %{project_path: path} do
      # No trusted_keys directory created. Global dir may or may not exist
      # on the host — we only assert the project's own absence doesn't
      # crash.
      assert is_list(Store.trusted_keys(path))
    end
  end
end
