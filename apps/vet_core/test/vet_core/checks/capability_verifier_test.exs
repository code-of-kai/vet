defmodule VetCore.Checks.CapabilityVerifierTest do
  use ExUnit.Case, async: false

  alias VetCore.Checks.CapabilityVerifier
  alias VetCore.Types.Dependency

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_cap_test_#{unique}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep"])
    ebin = Path.join([tmp_dir, "_build", "dev", "lib", "test_dep", "ebin"])
    File.mkdir_p!(dep_dir)
    File.mkdir_p!(ebin)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, dep_dir: dep_dir, ebin: ebin, unique: unique}
  end

  defp dep do
    %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
  end

  defp write_mix(dep_dir, body) do
    File.write!(Path.join(dep_dir, "mix.exs"), body)
  end

  defp compile_to(ebin, source, module_name) do
    [{^module_name, beam_bin}] = Code.compile_string(source)
    suffix = module_name |> Atom.to_string() |> String.replace_prefix("Elixir.", "")
    File.write!(Path.join(ebin, "#{suffix}.beam"), beam_bin)
  end

  defp run(tmp), do: CapabilityVerifier.run(dep(), tmp, [])

  test "no findings when mix.exs does not declare :vet_capabilities", %{
    tmp_dir: tmp,
    dep_dir: dep_dir
  } do
    write_mix(dep_dir, """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project, do: [app: :test_dep, version: "1.0.0"]
    end
    """)

    findings = run(tmp)
    assert findings == []
  end

  test "fires :capability_undeclared_use when BEAM imports :ssh but :vet_capabilities is empty",
       %{tmp_dir: tmp, dep_dir: dep_dir, ebin: ebin, unique: u} do
    write_mix(dep_dir, """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project, do: [app: :test_dep, version: "1.0.0", vet_capabilities: []]
    end
    """)

    module = Module.concat([Vet.CapTest, "Sshy#{u}"])

    compile_to(
      ebin,
      """
      defmodule Vet.CapTest.Sshy#{u} do
        def go, do: :ssh.connect(~c"h", 22, [])
      end
      """,
      module
    )

    findings = run(tmp)

    # :ssh maps to capabilities :ssh and :network — both should be flagged
    assert Enum.any?(findings, fn f ->
             f.check_id == :capability_undeclared_use and
               String.contains?(f.description, ":ssh")
           end)

    assert Enum.any?(findings, fn f ->
             f.check_id == :capability_undeclared_use and
               String.contains?(f.description, ":network")
           end)
  end

  test "no undeclared findings when capability is declared", %{
    tmp_dir: tmp,
    dep_dir: dep_dir,
    ebin: ebin,
    unique: u
  } do
    write_mix(dep_dir, """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project, do: [app: :test_dep, version: "1.0.0",
                        vet_capabilities: [:ssh, :network]]
    end
    """)

    module = Module.concat([Vet.CapTest, "Declared#{u}"])

    compile_to(
      ebin,
      """
      defmodule Vet.CapTest.Declared#{u} do
        def go, do: :ssh.connect(~c"h", 22, [])
      end
      """,
      module
    )

    findings = run(tmp)
    assert Enum.all?(findings, &(&1.check_id != :capability_undeclared_use))
  end

  test "fires :capability_declared_unused when capability declared but not exercised", %{
    tmp_dir: tmp,
    dep_dir: dep_dir,
    ebin: ebin,
    unique: u
  } do
    write_mix(dep_dir, """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project, do: [app: :test_dep, version: "1.0.0",
                        vet_capabilities: [:network]]
    end
    """)

    module = Module.concat([Vet.CapTest, "NoNet#{u}"])

    compile_to(
      ebin,
      """
      defmodule Vet.CapTest.NoNet#{u} do
        def add(a, b), do: a + b
      end
      """,
      module
    )

    findings = run(tmp)

    assert Enum.any?(findings, fn f ->
             f.check_id == :capability_declared_unused and
               String.contains?(f.description, ":network")
           end)
  end

  test "fires :capability_unknown for invalid capability atoms", %{
    tmp_dir: tmp,
    dep_dir: dep_dir
  } do
    write_mix(dep_dir, """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project, do: [app: :test_dep, version: "1.0.0",
                        vet_capabilities: [:bogus_capability]]
    end
    """)

    findings = run(tmp)

    assert Enum.any?(findings, fn f ->
             f.check_id == :capability_unknown and
               String.contains?(f.description, ":bogus_capability")
           end)
  end

  test "native artifact in priv/ surfaces as :native capability", %{
    tmp_dir: tmp,
    dep_dir: dep_dir
  } do
    File.mkdir_p!(Path.join(dep_dir, "priv"))
    File.write!(Path.join([dep_dir, "priv", "thing.so"]), "fake")

    write_mix(dep_dir, """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project, do: [app: :test_dep, version: "1.0.0",
                        vet_capabilities: []]
    end
    """)

    findings = run(tmp)

    assert Enum.any?(findings, fn f ->
             f.check_id == :capability_undeclared_use and
               String.contains?(f.description, ":native")
           end)
  end

  test "valid_capabilities/0 includes the published list" do
    caps = CapabilityVerifier.valid_capabilities()
    assert :network in caps
    assert :file_read in caps
    assert :file_write in caps
    assert :system_exec in caps
    assert :code_eval in caps
    assert :native in caps
    assert :compile_hook in caps
    assert :reflection in caps
    assert :ssh in caps
    assert :env_access in caps
  end

  test "no findings if dep dir does not exist", %{tmp_dir: tmp} do
    bad_dep = %Dependency{name: :no_such_dep, version: "1.0.0", source: :hex}
    assert CapabilityVerifier.run(bad_dep, tmp, []) == []
  end
end
