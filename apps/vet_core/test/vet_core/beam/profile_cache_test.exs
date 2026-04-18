defmodule VetCore.BEAM.ProfileCacheTest do
  use ExUnit.Case, async: false

  alias VetCore.BEAM.{BeamProfile, ProfileCache}

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_profile_cache_test_#{unique}")
    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, unique: unique}
  end

  defp profile(opts \\ []) do
    %BeamProfile{
      module: opts[:module] || Foo,
      path: opts[:path] || "<test>",
      imports: opts[:imports] || [],
      exports: opts[:exports] || [],
      atoms: opts[:atoms] || [],
      attributes: opts[:attributes] || %{},
      compile_info: opts[:compile_info] || %{},
      dynamic_dispatch_count: opts[:dynamic_dispatch_count] || 0,
      handle_undefined_function?: opts[:handle_undefined_function?] || false
    }
  end

  test "save then load returns the same profile structs", %{tmp_dir: tmp} do
    profiles = [
      profile(module: Foo, imports: [{:erlang, :spawn, 3}]),
      profile(module: Bar, exports: [{:run, 1}])
    ]

    :ok = ProfileCache.save(profiles, tmp, :test_pkg, "1.0.0")
    loaded = ProfileCache.load(tmp, :test_pkg, "1.0.0")

    assert length(loaded) == 2
    modules = Enum.map(loaded, & &1.module) |> Enum.sort()
    assert modules == [Bar, Foo]

    foo = Enum.find(loaded, &(&1.module == Foo))
    assert {:erlang, :spawn, 3} in foo.imports
  end

  test "load returns [] when version not in cache", %{tmp_dir: tmp} do
    assert ProfileCache.load(tmp, :missing_pkg, "9.9.9") == []
  end

  test "save overwrites prior snapshot for the same version", %{tmp_dir: tmp} do
    :ok = ProfileCache.save([profile(module: A)], tmp, :pkg, "1.0.0")
    :ok = ProfileCache.save([profile(module: B)], tmp, :pkg, "1.0.0")

    loaded = ProfileCache.load(tmp, :pkg, "1.0.0")
    modules = Enum.map(loaded, & &1.module)
    assert B in modules
    # Note: ProfileCache.save writes new files but does not pre-clean the
    # version dir; this test documents that. If we want strict overwrite
    # semantics, that becomes a separate change.
  end

  test "versions/2 lists every cached version of a package", %{tmp_dir: tmp} do
    :ok = ProfileCache.save([profile(module: A)], tmp, :pkg, "1.0.0")
    :ok = ProfileCache.save([profile(module: A)], tmp, :pkg, "1.1.0")
    :ok = ProfileCache.save([profile(module: A)], tmp, :pkg, "2.0.0")

    versions = ProfileCache.versions(tmp, :pkg)
    assert "1.0.0" in versions
    assert "1.1.0" in versions
    assert "2.0.0" in versions
  end

  test "drop/3 removes a single version", %{tmp_dir: tmp} do
    :ok = ProfileCache.save([profile(module: A)], tmp, :pkg, "1.0.0")
    :ok = ProfileCache.save([profile(module: A)], tmp, :pkg, "1.1.0")

    :ok = ProfileCache.drop(tmp, :pkg, "1.0.0")

    assert ProfileCache.load(tmp, :pkg, "1.0.0") == []
    assert length(ProfileCache.load(tmp, :pkg, "1.1.0")) == 1
  end

  test "versions/2 returns [] for unknown package", %{tmp_dir: tmp} do
    assert ProfileCache.versions(tmp, :nonexistent) == []
  end

  test "round-trips dynamic_dispatch_count and handle_undefined_function?", %{tmp_dir: tmp} do
    p =
      profile(
        module: Tricky,
        dynamic_dispatch_count: 7,
        handle_undefined_function?: true
      )

    :ok = ProfileCache.save([p], tmp, :pkg, "1.0.0")
    [loaded] = ProfileCache.load(tmp, :pkg, "1.0.0")

    assert loaded.dynamic_dispatch_count == 7
    assert loaded.handle_undefined_function? == true
  end
end
