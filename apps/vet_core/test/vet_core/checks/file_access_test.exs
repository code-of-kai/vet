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

  describe "sensitive-path detection — evasion via non-literal arguments" do
    # These tests attack the promise that "sensitive path access → critical".
    # `args_contain_sensitive_path?/1` only inspects binary/charlist/binary-ctor
    # literals; any construct that defers the path value to runtime — a variable,
    # Path.join, module attribute, etc. — slips past. The check still fires (any
    # File.read! is flagged) but at :warning, not :critical, silently losing the
    # credential-exfiltration signal.
    #
    # Each test below pins a concrete evasion so that if the matcher ever grows
    # data-flow awareness, the test breaks and we update the expectation.

    test "sensitive path through a local variable is NOT elevated to critical",
         %{tmp_dir: tmp_dir} do
      # `File.read!(path)` where path = "~/.ssh/id_rsa". The string literal is
      # syntactically visible a few lines up but the matcher only sees the
      # variable reference as the argument → the sensitive-path check misses it.
      source = """
      defmodule Evasion.Variable do
        def steal do
          path = "~/.ssh/id_rsa"
          File.read!(path)
        end
      end
      """

      findings = run_check(tmp_dir, source)
      read_findings = Enum.filter(findings, &(&1.description =~ "File.read!"))

      assert read_findings != [], "expected at least one File.read! finding"

      refute Enum.any?(read_findings, &(&1.severity == :critical)),
             "variable-resolution would have promoted to critical; if that's now working, " <>
               "update this test. Current findings: " <>
               inspect(Enum.map(read_findings, &{&1.severity, &1.description}))
    end

    test "sensitive path assembled via Path.join is NOT elevated to critical",
         %{tmp_dir: tmp_dir} do
      # Path.join("~/", ".ssh/id_rsa") evaluates to "~/.ssh/id_rsa" at runtime
      # but the AST argument is a call expression, not a binary. Missed.
      source = """
      defmodule Evasion.PathJoin do
        def steal do
          File.read!(Path.join("~/", ".ssh/id_rsa"))
        end
      end
      """

      findings = run_check(tmp_dir, source)
      read_findings = Enum.filter(findings, &(&1.description =~ "File.read!"))

      assert read_findings != []

      refute Enum.any?(read_findings, &(&1.severity == :critical)),
             "Path.join-assembled sensitive paths should now be caught if this fails"
    end

    test "sensitive path via string interpolation with dynamic middle IS caught when a literal segment contains the marker",
         %{tmp_dir: tmp_dir} do
      # Reverse-adversarial: assert the matcher's CURRENT positive behavior on
      # interpolated binaries. "~/.ssh/#{name}" has a literal segment "~/.ssh/"
      # that contains the marker "~/.ssh" → elevated. This is the one
      # runtime-ish case the check does handle.
      source = """
      defmodule Evasion.Interp do
        def steal(name) do
          File.read!("~/.ssh/\#{name}")
        end
      end
      """

      findings = run_check(tmp_dir, source)
      read_findings = Enum.filter(findings, &(&1.description =~ "File.read!"))

      assert Enum.any?(read_findings, &(&1.severity == :critical)),
             "expected interpolation with literal sensitive prefix to stay critical"
    end

    test "sensitive path split across concatenation — only the left literal matters",
         %{tmp_dir: tmp_dir} do
      # "~/.ssh/" <> name — left side "~/.ssh/" contains "~/.ssh", so the
      # `:<<>>` path SHOULD pick this up. But the AST form of `<>` is actually
      # `{:<>, _, [left, right]}` at parse time, *not* `{:<<>>, _, parts}`.
      # That's a separate AST node from interpolation — so this case is missed.
      source = """
      defmodule Evasion.Concat do
        def steal(name) do
          File.read!("~/.ssh/" <> name)
        end
      end
      """

      findings = run_check(tmp_dir, source)
      read_findings = Enum.filter(findings, &(&1.description =~ "File.read!"))

      assert read_findings != []

      refute Enum.any?(read_findings, &(&1.severity == :critical)),
             "<> concat on sensitive literal prefix is currently missed; " <>
               "if a literal-prefix check was added, update this test"
    end
  end
end
