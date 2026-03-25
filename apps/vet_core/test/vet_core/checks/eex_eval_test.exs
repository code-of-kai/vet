defmodule VetCore.Checks.EExEvalTest do
  use ExUnit.Case

  alias VetCore.Checks.EExEval
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_eex_eval_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    EExEval.run(dep, tmp_dir, [])
  end

  test "detects EEx.eval_string", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def render(template, bindings) do
        EEx.eval_string(template, bindings)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :eex_eval
    assert finding.category == :code_eval
    assert finding.severity == :critical
    assert finding.description =~ "EEx.eval_string"
  end

  test "detects EEx.eval_file", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def render(path) do
        EEx.eval_file(path)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :eex_eval
    assert finding.severity == :critical
    assert finding.description =~ "EEx.eval_file"
  end

  test "detects EEx.compile_string with lower severity", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def compile(template) do
        EEx.compile_string(template)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :eex_eval
    assert finding.severity == :warning
    assert finding.description =~ "EEx.compile_string"
  end

  test "detects EEx.compile_file with lower severity", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def compile(path) do
        EEx.compile_file(path)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :eex_eval
    assert finding.severity == :warning
    assert finding.description =~ "EEx.compile_file"
  end

  test "compile-time EEx.compile_string escalates to critical", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @compiled EEx.compile_string("<%= x %>")
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
      def math(x), do: x * 2
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
