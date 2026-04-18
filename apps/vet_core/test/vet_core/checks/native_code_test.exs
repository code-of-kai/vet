defmodule VetCore.Checks.NativeCodeTest do
  use ExUnit.Case, async: false

  alias VetCore.Checks.NativeCode
  alias VetCore.Types.Dependency

  setup do
    unique = System.unique_integer([:positive])
    tmp_dir = Path.join(System.tmp_dir!(), "vet_native_test_#{unique}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep"])
    File.mkdir_p!(dep_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, dep_dir: dep_dir, unique: unique}
  end

  defp run(tmp_dir) do
    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    NativeCode.run(dep, tmp_dir, [])
  end

  test "no findings when dep dir does not exist" do
    tmp = Path.join(System.tmp_dir!(), "vet_no_dep_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)

    assert run(tmp) == []
  end

  test "fires on shipped .so artifact in priv/", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    priv = Path.join(dep_dir, "priv")
    File.mkdir_p!(priv)
    File.write!(Path.join(priv, "nif.so"), "fake binary")

    findings = run(tmp_dir)

    assert Enum.any?(findings, fn f ->
             f.check_id == :native_code_artifact and f.severity == :critical and
               String.contains?(f.description, "priv/nif.so")
           end)
  end

  test "fires on shipped .dylib in priv/", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    priv = Path.join(dep_dir, "priv")
    File.mkdir_p!(priv)
    File.write!(Path.join(priv, "lib_native.dylib"), "fake")

    findings = run(tmp_dir)
    assert Enum.any?(findings, &(&1.check_id == :native_code_artifact))
  end

  test "fires on shipped .dll in priv/", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    priv = Path.join(dep_dir, "priv")
    File.mkdir_p!(priv)
    File.write!(Path.join(priv, "win.dll"), "fake")

    findings = run(tmp_dir)
    assert Enum.any?(findings, &(&1.check_id == :native_code_artifact))
  end

  test "fires on c_src/ directory", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.mkdir_p!(Path.join(dep_dir, "c_src"))

    findings = run(tmp_dir)

    assert Enum.any?(findings, fn f ->
             f.check_id == :native_code_source and f.severity == :warning and
               f.compile_time? == true and
               String.contains?(f.description, "c_src/")
           end)
  end

  test "fires on native/ directory", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.mkdir_p!(Path.join(dep_dir, "native"))

    findings = run(tmp_dir)
    assert Enum.any?(findings, &(&1.check_id == :native_code_source))
  end

  test "fires on Makefile at package root", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.write!(Path.join(dep_dir, "Makefile"), "all:\n\techo hi\n")

    findings = run(tmp_dir)

    assert Enum.any?(findings, fn f ->
             f.check_id == :native_code_build_file and
               String.contains?(f.description, "Makefile")
           end)
  end

  test "fires on Cargo.toml at package root", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.write!(Path.join(dep_dir, "Cargo.toml"), "[package]\nname = \"x\"\n")

    findings = run(tmp_dir)
    assert Enum.any?(findings, &(&1.check_id == :native_code_build_file))
  end

  test "fires on build.zig at package root", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.write!(Path.join(dep_dir, "build.zig"), "// zig build")

    findings = run(tmp_dir)
    assert Enum.any?(findings, &(&1.check_id == :native_code_build_file))
  end

  test "fires when mix.exs declares :elixir_make compiler", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.write!(Path.join(dep_dir, "mix.exs"), """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project do
        [app: :test_dep, version: "1.0.0", compilers: [:elixir_make] ++ Mix.compilers()]
      end
    end
    """)

    findings = run(tmp_dir)

    assert Enum.any?(findings, fn f ->
             f.check_id == :native_code_compiler and
               String.contains?(f.description, ":elixir_make")
           end)
  end

  test "fires when mix.exs declares :rustler compiler", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.write!(Path.join(dep_dir, "mix.exs"), """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project do
        [app: :test_dep, version: "1.0.0", compilers: [:rustler] ++ Mix.compilers()]
      end
    end
    """)

    findings = run(tmp_dir)
    assert Enum.any?(findings, &(&1.check_id == :native_code_compiler))
  end

  test "no false positive on a pure-Elixir mix.exs", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.write!(Path.join(dep_dir, "mix.exs"), """
    defmodule TestDep.MixProject do
      use Mix.Project
      def project do
        [app: :test_dep, version: "1.0.0"]
      end
    end
    """)

    findings = run(tmp_dir)
    assert Enum.all?(findings, &(&1.check_id != :native_code_compiler))
  end

  test "fires on BEAM importing :erlang.load_nif/2", %{tmp_dir: tmp_dir, unique: u} do
    ebin = Path.join([tmp_dir, "_build", "dev", "lib", "test_dep", "ebin"])
    File.mkdir_p!(ebin)

    module = Module.concat([Vet.NativeCodeTest, "Loader#{u}"])

    source = """
    defmodule Vet.NativeCodeTest.Loader#{u} do
      @on_load :init
      def init, do: :erlang.load_nif(~c"priv/nif", 0)
      def hello, do: :erlang.nif_error(:not_loaded)
    end
    """

    [{^module, beam_bin}] = Code.compile_string(source)
    suffix = module |> Atom.to_string() |> String.replace_prefix("Elixir.", "")
    File.write!(Path.join(ebin, "#{suffix}.beam"), beam_bin)

    findings = run(tmp_dir)

    assert Enum.any?(findings, fn f ->
             f.check_id == :native_code_load_nif and f.severity == :critical and
               String.contains?(f.description, ":erlang.load_nif")
           end)
  end

  test "safe pure-Elixir package produces no findings", %{tmp_dir: tmp_dir, dep_dir: dep_dir} do
    File.mkdir_p!(Path.join(dep_dir, "lib"))

    File.write!(Path.join([dep_dir, "lib", "thing.ex"]), """
    defmodule Thing do
      def add(a, b), do: a + b
    end
    """)

    File.write!(Path.join(dep_dir, "mix.exs"), """
    defmodule Thing.MixProject do
      use Mix.Project
      def project do
        [app: :test_dep, version: "1.0.0"]
      end
    end
    """)

    findings = run(tmp_dir)
    assert findings == []
  end

  test "no false positive when priv/ contains only data files", %{
    tmp_dir: tmp_dir,
    dep_dir: dep_dir
  } do
    priv = Path.join(dep_dir, "priv")
    File.mkdir_p!(priv)
    File.write!(Path.join(priv, "data.json"), "{}")
    File.write!(Path.join(priv, "static.html"), "<html/>")

    findings = run(tmp_dir)
    assert Enum.all?(findings, &(&1.check_id != :native_code_artifact))
  end
end
