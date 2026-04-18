defmodule VetCore.Checks.BeamDeltaTest do
  use ExUnit.Case, async: false

  alias VetCore.BEAM.{BeamProfile, ProfileCache}
  alias VetCore.Checks.BeamDelta
  alias VetCore.Types.Dependency

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_beam_delta_test_#{unique}")
    ebin = Path.join([tmp_dir, "_build", "dev", "lib", "test_dep", "ebin"])
    File.mkdir_p!(ebin)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, ebin: ebin, unique: unique}
  end

  defp dep(version) do
    %Dependency{name: :test_dep, version: version, source: :hex}
  end

  defp compile_to(ebin, source, module_name) do
    [{^module_name, beam_bin}] = Code.compile_string(source)
    suffix = module_name |> Atom.to_string() |> String.replace_prefix("Elixir.", "")
    File.write!(Path.join(ebin, "#{suffix}.beam"), beam_bin)
  end

  defp prime_cache(tmp_dir, version, profiles) do
    ProfileCache.save(profiles, tmp_dir, :test_dep, version)
  end

  test "no findings when no prior version is cached", %{tmp_dir: tmp, ebin: ebin, unique: u} do
    module = Module.concat([Vet.BeamDeltaTest, "Fresh#{u}"])

    source = """
    defmodule Vet.BeamDeltaTest.Fresh#{u} do
      def run, do: :ok
    end
    """

    compile_to(ebin, source, module)

    findings = BeamDelta.run(dep("1.0.0"), tmp, [])
    assert findings == []
  end

  test "fires on dangerous import added between versions", %{
    tmp_dir: tmp,
    ebin: ebin,
    unique: u
  } do
    module = Module.concat([Vet.BeamDeltaTest, "Mod#{u}"])
    module_str = "Vet.BeamDeltaTest.Mod#{u}"

    # Prior version: benign
    prior_profile = %BeamProfile{
      module: module,
      path: "<prior>",
      imports: [{:erlang, :length, 1}],
      exports: [{:run, 0}],
      atoms: [],
      attributes: %{},
      compile_info: %{},
      dynamic_dispatch_count: 0,
      handle_undefined_function?: false
    }

    prime_cache(tmp, "1.0.0", [prior_profile])

    # Current version compiled from source — adds :ssh.connect/3
    source = """
    defmodule #{module_str} do
      def run, do: :ssh.connect(~c"host", 22, [])
    end
    """

    compile_to(ebin, source, module)

    findings = BeamDelta.run(dep("1.1.0"), tmp, [])

    assert Enum.any?(findings, fn f ->
             f.check_id == :beam_delta_dangerous_import and
               f.severity == :critical and
               String.contains?(f.description, ":ssh") and
               String.contains?(f.description, "1.0.0") and
               String.contains?(f.description, "1.1.0")
           end)
  end

  test "fires on $handle_undefined_function newly exported", %{
    tmp_dir: tmp,
    ebin: ebin,
    unique: u
  } do
    module = Module.concat([Vet.BeamDeltaTest, "Sneaky#{u}"])
    module_str = "Vet.BeamDeltaTest.Sneaky#{u}"

    prior_profile = %BeamProfile{
      module: module,
      path: "<prior>",
      imports: [],
      exports: [{:run, 0}],
      atoms: [],
      attributes: %{},
      compile_info: %{},
      dynamic_dispatch_count: 0,
      handle_undefined_function?: false
    }

    prime_cache(tmp, "1.0.0", [prior_profile])

    source = """
    defmodule #{module_str} do
      def unquote(:"$handle_undefined_function")(name, args), do: {name, args}
    end
    """

    compile_to(ebin, source, module)

    findings = BeamDelta.run(dep("1.1.0"), tmp, [])

    assert Enum.any?(findings, fn f ->
             f.check_id == :beam_delta_handle_undefined and
               f.severity == :critical
           end)
  end

  test "fires on newly added module", %{tmp_dir: tmp, ebin: ebin, unique: u} do
    existing_module = Module.concat([Vet.BeamDeltaTest, "Existing#{u}"])

    prior_profile = %BeamProfile{
      module: existing_module,
      path: "<prior>",
      imports: [],
      exports: [{:run, 0}],
      atoms: [],
      attributes: %{},
      compile_info: %{},
      dynamic_dispatch_count: 0,
      handle_undefined_function?: false
    }

    prime_cache(tmp, "1.0.0", [prior_profile])

    # Add a brand-new module in the current version
    new_module = Module.concat([Vet.BeamDeltaTest, "BrandNew#{u}"])
    new_module_str = "Vet.BeamDeltaTest.BrandNew#{u}"

    new_source = """
    defmodule #{new_module_str} do
      def run, do: :ok
    end
    """

    existing_source = """
    defmodule Vet.BeamDeltaTest.Existing#{u} do
      def run, do: :ok
    end
    """

    compile_to(ebin, existing_source, existing_module)
    compile_to(ebin, new_source, new_module)

    findings = BeamDelta.run(dep("1.1.0"), tmp, [])

    assert Enum.any?(findings, fn f ->
             f.check_id == :beam_delta_module_added and
               String.contains?(f.description, "BrandNew")
           end)
  end

  test "newly added module that imports :ssh fires both module_added and dangerous_import",
       %{tmp_dir: tmp, ebin: ebin, unique: u} do
    existing_module = Module.concat([Vet.BeamDeltaTest, "Existing#{u}"])

    prior_profile = %BeamProfile{
      module: existing_module,
      path: "<prior>",
      imports: [],
      exports: [{:run, 0}],
      atoms: [],
      attributes: %{},
      compile_info: %{},
      dynamic_dispatch_count: 0,
      handle_undefined_function?: false
    }

    prime_cache(tmp, "1.0.0", [prior_profile])

    new_module = Module.concat([Vet.BeamDeltaTest, "Sneaky#{u}"])
    new_module_str = "Vet.BeamDeltaTest.Sneaky#{u}"

    new_source = """
    defmodule #{new_module_str} do
      def go, do: :ssh.connect(~c"h", 22, [])
    end
    """

    existing_source = """
    defmodule Vet.BeamDeltaTest.Existing#{u} do
      def run, do: :ok
    end
    """

    compile_to(ebin, existing_source, existing_module)
    compile_to(ebin, new_source, new_module)

    findings = BeamDelta.run(dep("1.1.0"), tmp, [])

    check_ids = Enum.map(findings, & &1.check_id)
    assert :beam_delta_module_added in check_ids
    assert :beam_delta_dangerous_import in check_ids
  end

  test "snapshot/3 caches the current build", %{tmp_dir: tmp, ebin: ebin, unique: u} do
    module = Module.concat([Vet.BeamDeltaTest, "Snap#{u}"])

    source = """
    defmodule Vet.BeamDeltaTest.Snap#{u} do
      def run, do: :ok
    end
    """

    compile_to(ebin, source, module)

    :ok = BeamDelta.snapshot(:test_dep, "1.0.0", tmp)

    profiles = ProfileCache.load(tmp, :test_dep, "1.0.0")
    assert length(profiles) >= 1
    assert Enum.any?(profiles, &(&1.module == module))
  end

  test "snapshot is a no-op when no _build artifacts present", %{tmp_dir: tmp} do
    # No ebin populated for this test — wipe it
    File.rm_rf!(Path.join([tmp, "_build"]))

    assert :ok == BeamDelta.snapshot(:test_dep, "1.0.0", tmp)
    assert ProfileCache.load(tmp, :test_dep, "1.0.0") == []
  end

  test "no findings when dep version is nil", %{tmp_dir: tmp} do
    assert BeamDelta.run(%Dependency{name: :test_dep, version: nil, source: :hex}, tmp, []) == []
  end
end
