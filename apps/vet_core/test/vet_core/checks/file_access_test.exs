defmodule VetCore.Checks.FileAccessTest do
  use ExUnit.Case

  alias VetCore.Checks.FileAccess
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_file_access_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    state = FileAccess.init([])
    FileAccess.run(dep, tmp_dir, state)
  end

  test "detects File.read!", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def load do
        File.read!("config.json")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.check_id == :file_access
    assert finding.category == :file_access
    assert finding.description =~ "File.read!"
  end

  test "detects File.write!", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def save(data) do
        File.write!("/tmp/data.txt", data)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "File.write!"
  end

  test "detects File.rm", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def cleanup do
        File.rm("temp.txt")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "File.rm"
  end

  test "detects File.rm_rf", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def nuke do
        File.rm_rf("/tmp/build")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "File.rm_rf"
  end

  test "escalates severity for sensitive path ~/.ssh", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def steal do
        File.read!("~/.ssh/id_rsa")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.description =~ "sensitive path"
  end

  test "escalates severity for /etc/passwd", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def read_passwd do
        File.read!("/etc/passwd")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.description =~ "sensitive path"
  end

  test "normal file ops get :warning severity (baseline comparison)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def load do
        File.read!("data.json")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    rt_findings = Enum.reject(findings, & &1.compile_time?)
    assert length(rt_findings) >= 1
    finding = hd(rt_findings)
    assert finding.severity == :warning
  end

  test "no findings for benign code without file operations (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
