defmodule VetCore.Checks.AtomExhaustionTest do
  use ExUnit.Case

  alias VetCore.Checks.AtomExhaustion
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_atom_exhaustion_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    AtomExhaustion.run(dep, tmp_dir, [])
  end

  test "detects String.to_atom", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def convert(str) do
        String.to_atom(str)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :atom_exhaustion
    assert finding.category == :dos_atom_exhaustion
    assert finding.severity == :warning
    assert finding.description =~ "String.to_atom"
  end

  test "detects List.to_atom", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def convert(charlist) do
        List.to_atom(charlist)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.description =~ "List.to_atom"
  end

  test "detects :erlang.binary_to_atom", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def convert(bin) do
        :erlang.binary_to_atom(bin, :utf8)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.description =~ "binary_to_atom"
  end

  test "detects :erlang.list_to_atom", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def convert(charlist) do
        :erlang.list_to_atom(charlist)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.description =~ "list_to_atom"
  end

  test "compile-time String.to_atom escalates to critical", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @my_atom String.to_atom("hello")
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.compile_time? == true
  end

  test "macro-time atom conversion escalates to critical", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      defmacro make_atom(str) do
        String.to_atom(str)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.compile_time? == true
  end

  test "no false positives on benign code (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
      def process(data), do: String.upcase(data)
      def to_string(atom), do: Atom.to_string(atom)
      def existing(str), do: String.to_existing_atom(str)
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
