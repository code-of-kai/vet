defmodule VetCore.Checks.EnvAccessTest do
  use ExUnit.Case

  alias VetCore.Checks.EnvAccess
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_env_access_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    EnvAccess.run(dep, tmp_dir, [])
  end

  test "System.get_env/0 (whole env dump) gets :critical", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def dump do
        System.get_env()
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.description =~ "get_env/0"
  end

  test "System.get_env(\"NORMAL_VAR\") gets :warning", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def read do
        System.get_env("NORMAL_VAR")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :warning
    assert finding.description =~ "NORMAL_VAR"
  end

  test "System.get_env(\"AWS_SECRET_ACCESS_KEY\") gets :critical (sensitive pattern)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def read do
        System.get_env("AWS_SECRET_ACCESS_KEY")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.description =~ "sensitive"
  end

  test "System.fetch_env!(\"DATABASE_URL\") gets :critical", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def read do
        System.fetch_env!("DATABASE_URL")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :critical
    assert finding.description =~ "sensitive"
  end

  test "System.get_env(\"HOME\") gets :warning (non-sensitive, baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def read do
        System.get_env("HOME")
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    finding = hd(findings)
    assert finding.severity == :warning
    assert finding.description =~ "HOME"
  end

  test "no findings for code without env access (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
