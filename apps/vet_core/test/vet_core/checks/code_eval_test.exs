defmodule VetCore.Checks.CodeEvalTest do
  use ExUnit.Case

  alias VetCore.Checks.CodeEval
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_code_eval_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    state = CodeEval.init([])
    CodeEval.run(dep, tmp_dir, state)
  end

  test "detects Code.eval_string", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run(code) do
        Code.eval_string(code)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :code_eval
    assert finding.category == :code_eval
    assert String.contains?(finding.description, "Code.eval_string")
  end

  test "detects Code.eval_quoted", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run(ast) do
        Code.eval_quoted(ast)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Code.eval_quoted"
  end

  test "detects Code.eval_file", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run(path) do
        Code.eval_file(path)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Code.eval_file"
  end

  test "detects Code.compile_string", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run(code) do
        Code.compile_string(code)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Code.compile_string"
  end

  test "detects :erlang.binary_to_term", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def deserialize(bin) do
        :erlang.binary_to_term(bin)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "binary_to_term"
  end

  test "detects Module.create/3", %{tmp_dir: tmp_dir} do
    source = ~S"""
    defmodule TestMod do
      def make_module(name) do
        Module.create(name, (quote do: nil), __ENV__)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Module.create"
  end

  test "no false positives on benign code (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
      def process(data), do: String.upcase(data)
      def math(x), do: x * 2
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
