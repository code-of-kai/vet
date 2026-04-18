defmodule VetCore.Checks.AttestationTest do
  use ExUnit.Case, async: true

  alias VetCore.Attestation.{Manifest, Signer, Store}
  alias VetCore.BEAM.BeamProfile
  alias VetCore.Checks.Attestation

  setup do
    tmp = Path.join(System.tmp_dir!(), "vet_attestation_check_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)
    {:ok, project_path: tmp}
  end

  describe "run/3 in :advisory mode (default)" do
    test "emits no findings when no manifest is present", %{project_path: path} do
      dep = %{name: :ghost_pkg, version: "1.0.0"}
      assert Attestation.run(dep, path, []) == []
    end

    test "emits no findings on a stringy version", %{project_path: path} do
      dep = %{name: :p, version: "1.0.0"}
      assert Attestation.run(dep, path, attestation: :advisory) == []
    end
  end

  describe "run/3 in :require mode" do
    test "emits warning when no manifest is present", %{project_path: path} do
      dep = %{name: :p, version: "1.0.0"}

      [finding] = Attestation.run(dep, path, attestation: :require)

      assert finding.check_id == :attestation_unsigned
      assert finding.severity == :warning
      assert finding.dep_name == :p
      assert finding.description =~ "no signed manifest"
    end
  end

  describe "run/3 in :strict mode" do
    test "emits critical when no manifest is present", %{project_path: path} do
      dep = %{name: :p, version: "1.0.0"}

      [finding] = Attestation.run(dep, path, attestation: :strict)

      assert finding.check_id == :attestation_unsigned
      assert finding.severity == :critical
      assert finding.description =~ "strict"
    end
  end

  describe "run/3 with a signed manifest" do
    setup %{project_path: path} do
      # Fake a compiled ebin directory for package "demo" version "1.0.0"
      # at _build/dev/lib/demo/ebin with one real BEAM file.
      ebin = Path.join([path, "_build", "dev", "lib", "demo", "ebin"])
      File.mkdir_p!(ebin)
      {:ok, module_name} = compile_tiny_module(ebin)

      profiles = BeamProfile.build_all(ebin)
      assert profiles != []

      %{public: pub, private: priv} = Signer.generate_keypair()

      keys_dir = Path.join(path, ".vet/trusted_keys")
      File.mkdir_p!(keys_dir)
      File.write!(Path.join(keys_dir, "trusted.pub"), Signer.encode_key(pub, :public))

      {:ok,
       profiles: profiles,
       public_key: pub,
       private_key: priv,
       module_name: module_name}
    end

    test "emits no findings when install matches signed manifest", %{
      project_path: path,
      profiles: profiles,
      private_key: priv
    } do
      manifest = Manifest.build("demo", "1.0.0", profiles, [], "trusted")
      {_json, sig} = Signer.sign_manifest(manifest, priv)
      :ok = Store.save(path, manifest, sig)

      dep = %{name: :demo, version: "1.0.0"}
      assert Attestation.run(dep, path, []) == []
    end

    test "emits :attestation_untrusted when no trusted key matches", %{
      project_path: path,
      profiles: profiles
    } do
      # Sign with a throwaway key that is NOT in the trusted_keys dir.
      %{private: rogue_priv} = Signer.generate_keypair()
      manifest = Manifest.build("demo", "1.0.0", profiles, [], "rogue")
      {_json, sig} = Signer.sign_manifest(manifest, rogue_priv)
      :ok = Store.save(path, manifest, sig)

      dep = %{name: :demo, version: "1.0.0"}
      [finding] = Attestation.run(dep, path, [])

      assert finding.check_id == :attestation_untrusted
      assert finding.severity == :critical
      assert finding.description =~ "trusted public key"
    end

    test "emits :attestation_hash_mismatch when manifest hash disagrees with install", %{
      project_path: path,
      profiles: profiles,
      private_key: priv,
      module_name: module_name
    } do
      # Build a manifest claiming a fabricated content hash for the module.
      tampered_manifest = %Manifest{
        package: "demo",
        version: "1.0.0",
        module_hashes: [
          %{
            module: Atom.to_string(module_name),
            content_hash: "0000000000000000000000000000000000000000000000000000000000000000"
          }
        ],
        capabilities: [],
        signer: "trusted",
        signed_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        notes: nil
      }

      {_json, sig} = Signer.sign_manifest(tampered_manifest, priv)
      :ok = Store.save(path, tampered_manifest, sig)

      # Sanity: matching profile hash is different from the fabricated one.
      [profile | _] = profiles
      refute BeamProfile.content_hash(profile) ==
               "0000000000000000000000000000000000000000000000000000000000000000"

      dep = %{name: :demo, version: "1.0.0"}
      findings = Attestation.run(dep, path, [])

      assert Enum.all?(findings, &(&1.check_id == :attestation_hash_mismatch))
      assert Enum.all?(findings, &(&1.severity == :critical))
      assert Enum.any?(findings, &(&1.description =~ "module "))
    end
  end

  describe "run/3 guards" do
    test "returns [] when dep lacks a version", %{project_path: path} do
      dep = %{name: :no_version, version: nil}
      assert Attestation.run(dep, path, []) == []
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp compile_tiny_module(ebin) do
    mod_name = :"vet_att_check_mod_#{System.unique_integer([:positive])}"

    src = """
    -module(#{mod_name}).
    -export([noop/0]).
    noop() -> ok.
    """

    tmp_erl = Path.join(ebin, "#{mod_name}.erl")
    File.write!(tmp_erl, src)

    {:ok, ^mod_name} =
      :compile.file(String.to_charlist(tmp_erl), [
        {:outdir, String.to_charlist(ebin)},
        :return_errors
      ])

    File.rm!(tmp_erl)
    {:ok, mod_name}
  end
end
