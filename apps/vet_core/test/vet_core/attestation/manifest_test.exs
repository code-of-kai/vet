defmodule VetCore.Attestation.ManifestTest do
  use ExUnit.Case, async: true

  alias VetCore.Attestation.Manifest
  alias VetCore.BEAM.BeamProfile

  describe "build/6" do
    test "builds a manifest with sorted module hashes and capabilities" do
      profiles = [
        %BeamProfile{module: Foo, imports: [], exports: [], atoms: [], attributes: %{}},
        %BeamProfile{module: Bar, imports: [], exports: [], atoms: [], attributes: %{}}
      ]

      manifest = Manifest.build("my_pkg", "1.2.3", profiles, [:network, :file_read], "alice@example")

      assert manifest.package == "my_pkg"
      assert manifest.version == "1.2.3"
      assert Enum.map(manifest.module_hashes, & &1.module) == ["Elixir.Bar", "Elixir.Foo"]
      assert manifest.capabilities == [:file_read, :network]
      assert manifest.signer == "alice@example"
      assert is_binary(manifest.signed_at)
      assert manifest.notes == nil
    end

    test "respects :notes option" do
      manifest = Manifest.build("p", "1", [], [], "s", notes: "reviewed by security team")
      assert manifest.notes == "reviewed by security team"
    end
  end

  describe "to_canonical_json/1 and from_json/1" do
    test "round-trips a manifest losslessly" do
      profile = %BeamProfile{module: Foo, imports: [], exports: [], atoms: [], attributes: %{}}
      m = Manifest.build("pkg", "1.0.0", [profile], [:network], "signer")

      json = Manifest.to_canonical_json(m)
      {:ok, back} = Manifest.from_json(json)

      assert back.package == m.package
      assert back.version == m.version
      assert back.capabilities == m.capabilities
      assert back.signer == m.signer
      assert back.signed_at == m.signed_at
      assert back.module_hashes == m.module_hashes
    end

    test "canonical JSON is deterministic — same inputs produce identical bytes" do
      # build/6 sorts module_hashes and capabilities, so two manifests
      # constructed with different insertion orders but identical content
      # must serialize to the exact same bytes.
      profile_a = %BeamProfile{module: :"Elixir.A", imports: [], exports: [], atoms: [], attributes: %{}}
      profile_b = %BeamProfile{module: :"Elixir.B", imports: [], exports: [], atoms: [], attributes: %{}}

      built_one = Manifest.build("p", "1", [profile_a, profile_b], [:network, :file_read], "s")
      built_two = Manifest.build("p", "1", [profile_b, profile_a], [:file_read, :network], "s")

      built_one = %{built_one | signed_at: "2026-04-18T00:00:00Z"}
      built_two = %{built_two | signed_at: "2026-04-18T00:00:00Z"}

      assert Manifest.to_canonical_json(built_one) == Manifest.to_canonical_json(built_two)
    end

    test "from_json/1 returns :invalid_manifest for malformed JSON" do
      assert {:error, :invalid_manifest} = Manifest.from_json("not json at all")
    end

    test "from_json/1 handles missing fields by returning nil" do
      # The struct does not require every field to be populated — a
      # partially-valid manifest returns with nils for missing keys.
      {:ok, m} = Manifest.from_json(~s({"package":"p"}))
      assert m.package == "p"
      assert m.version == nil
      assert m.module_hashes == []
      assert m.capabilities == []
    end

    test "safe atom decoding drops unknown atoms" do
      # The Elixir runtime has :network (we reference it below) but
      # definitely does not have :this_capability_does_not_exist_ever.
      _ = :network
      json = ~s({"package":"p","version":"1","capabilities":["network","this_capability_does_not_exist_ever"]})
      {:ok, m} = Manifest.from_json(json)
      assert :network in m.capabilities
      refute Enum.any?(m.capabilities, &(to_string(&1) =~ "this_capability_does_not_exist"))
    end
  end
end
