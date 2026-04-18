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
    FileAccess.run(dep, tmp_dir, [])
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

  # --- Regression tests for GH issues #5 and #6 ---

  test "detects File.open! on sensitive path (GH #5)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo do
        f = File.open!("/etc/passwd")
        IO.read(f, :eof)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ "File.open!"))

    sensitive = Enum.find(findings, &(&1.severity == :critical))
    assert sensitive, "expected a critical finding for /etc/passwd access"
    assert sensitive.description =~ "sensitive path"
  end

  test "detects plain File.open (GH #5 non-bang form)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo(path) do
        File.open(path)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ "File.open"))
  end

  test "detects :file.read_file on sensitive path (GH #6)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def file do
        :file.read_file(~c"/etc/passwd")
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":file.read_file"))

    sensitive = Enum.find(findings, &(&1.severity == :critical))
    assert sensitive, "expected a critical finding for /etc/passwd access via :file"
  end

  test "detects :file.consult (GH #6)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def load do
        :file.consult(~c"config.exs")
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":file.consult"))
  end

  test "compile-time non-sensitive file read is :info (bundling pattern)",
       %{tmp_dir: tmp_dir} do
    # CT execution runs on the developer's machine — no user-input vector.
    # Whether the path is a string literal or a variable bound to one, the
    # developer can audit it. Exfil/eval risks are caught by Network /
    # CodeEval / Obfuscation checks separately. Surface as :info so the
    # user sees the CT file surface area without it inflating scores on
    # asset/template/version bundling (Phoenix, phoenix_live_dashboard,
    # phoenix_html, etc.).
    source = """
    defmodule TestMod do
      @version File.read!("VERSION")
      def version, do: @version
    end
    """

    findings = run_check(tmp_dir, source)

    finding = Enum.find(findings, &(&1.description =~ "File.read!" and &1.compile_time?))
    assert finding, "expected a compile-time finding for VERSION file read"
    assert finding.severity == :info,
           "compile-time non-sensitive file read should be :info"
    refute finding.severity == :critical,
           "compile-time non-sensitive file read should never escalate to :critical"
  end

  test "compile-time file read with variable path is also :info (asset bundling)",
       %{tmp_dir: tmp_dir} do
    # The canonical asset-bundling shape: bind a literal path to a var,
    # declare it as @external_resource, then File.read! the var. The AST
    # shows a variable, but the developer authored both the binding and
    # the read in the same module. Treat the same as the literal-path case.
    source = """
    defmodule TestMod do
      css_path = Path.join(__DIR__, "assets/app.css")
      @external_resource css_path
      @css File.read!(css_path)

      def css, do: @css
    end
    """

    findings = run_check(tmp_dir, source)

    finding = Enum.find(findings, &(&1.description =~ "File.read!" and &1.compile_time?))
    assert finding, "expected a CT File.read! finding"
    assert finding.severity == :info
  end

  test "compile-time sensitive file read remains :critical", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @secret File.read!("~/.ssh/id_rsa")
      def secret, do: @secret
    end
    """

    findings = run_check(tmp_dir, source)

    finding = Enum.find(findings, &(&1.severity == :critical))
    assert finding, "expected a critical finding for sensitive path read at compile time"
    assert finding.compile_time? == true
    assert finding.description =~ "sensitive"
  end
end
