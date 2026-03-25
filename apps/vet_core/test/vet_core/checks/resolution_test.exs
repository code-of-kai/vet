defmodule VetCore.Checks.ResolutionTest do
  @moduledoc """
  Integration tests verifying that alias resolution, import tracking, and
  variable-binding resolution close the three known evasion gaps across the
  full check pipeline.

  Each test creates a temporary fixture with specific evasion code, runs the
  relevant check, and asserts that findings are produced.
  """
  use ExUnit.Case, async: true

  alias VetCore.Checks.{SystemExec, CodeEval, FileAccess, EnvAccess, EExEval, AtomExhaustion}
  alias VetCore.Types.Dependency

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp create_fixture(dep_name, source) do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_resolution_test_#{:erlang.unique_integer([:positive])}"
      )

    dep_dir = Path.join([tmp_dir, "deps", to_string(dep_name), "lib"])
    File.mkdir_p!(dep_dir)
    File.write!(Path.join(dep_dir, "target.ex"), source)

    {tmp_dir, %Dependency{name: dep_name, version: "0.0.1", source: :hex, direct?: true}}
  end

  defp cleanup(tmp_dir) do
    File.rm_rf!(tmp_dir)
  end

  # ---------------------------------------------------------------------------
  # Alias resolution
  # ---------------------------------------------------------------------------

  describe "alias resolution" do
    test "detects Code.eval_string through alias" do
      {tmp, dep} =
        create_fixture(:alias_test, """
        defmodule Evil do
          alias Code, as: C
          def run, do: C.eval_string("1 + 1")
        end
        """)

      findings = CodeEval.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :code_eval))
    end

    test "detects System.cmd through alias" do
      {tmp, dep} =
        create_fixture(:alias_test2, """
        defmodule Evil do
          alias System, as: S
          def run, do: S.cmd("whoami", [])
        end
        """)

      findings = SystemExec.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :system_exec))
    end

    test "detects File.read! through alias" do
      {tmp, dep} =
        create_fixture(:alias_test3, """
        defmodule Evil do
          alias File, as: F
          def run, do: F.read!("/etc/passwd")
        end
        """)

      findings = FileAccess.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :file_access))
    end

    test "detects System.get_env through alias" do
      {tmp, dep} =
        create_fixture(:alias_test4, """
        defmodule Evil do
          alias System, as: Sys
          def run, do: Sys.get_env("AWS_SECRET_ACCESS_KEY")
        end
        """)

      findings = EnvAccess.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :env_access))
    end

    test "detects EEx.eval_string through alias" do
      {tmp, dep} =
        create_fixture(:alias_test5, """
        defmodule Evil do
          alias EEx, as: E
          def run, do: E.eval_string("<%= 1 + 1 %>")
        end
        """)

      findings = EExEval.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.check_id == :eex_eval))
    end
  end

  # ---------------------------------------------------------------------------
  # Import resolution
  # ---------------------------------------------------------------------------

  describe "import resolution" do
    test "detects cmd after import System" do
      {tmp, dep} =
        create_fixture(:import_test, """
        defmodule Evil do
          import System
          def run, do: cmd("whoami", [])
        end
        """)

      findings = SystemExec.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :system_exec))
    end

    test "detects eval_string after import Code" do
      {tmp, dep} =
        create_fixture(:import_test2, """
        defmodule Evil do
          import Code
          def run, do: eval_string("IO.puts :pwned")
        end
        """)

      findings = CodeEval.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :code_eval))
    end

    test "detects get_env after import System" do
      {tmp, dep} =
        create_fixture(:import_test3, """
        defmodule Evil do
          import System
          def run, do: get_env("SECRET_KEY")
        end
        """)

      findings = EnvAccess.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :env_access))
    end

    test "detects read! after import File" do
      {tmp, dep} =
        create_fixture(:import_test4, """
        defmodule Evil do
          import File
          def run, do: read!("/etc/passwd")
        end
        """)

      findings = FileAccess.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :file_access))
    end

    test "detects :os.cmd after import :os" do
      {tmp, dep} =
        create_fixture(:import_test5, """
        defmodule Evil do
          import :os
          def run, do: cmd(~c"whoami")
        end
        """)

      findings = SystemExec.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
    end
  end

  # ---------------------------------------------------------------------------
  # Variable binding resolution
  # ---------------------------------------------------------------------------

  describe "variable binding resolution" do
    test "detects cmd through variable-bound System" do
      {tmp, dep} =
        create_fixture(:var_test, """
        defmodule Evil do
          def run do
            mod = System
            mod.cmd("whoami", [])
          end
        end
        """)

      findings = SystemExec.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :system_exec))
    end

    test "detects eval_string through variable-bound Code" do
      {tmp, dep} =
        create_fixture(:var_test2, """
        defmodule Evil do
          def run do
            c = Code
            c.eval_string("dangerous")
          end
        end
        """)

      findings = CodeEval.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :code_eval))
    end

    test "detects :os.cmd through variable-bound Erlang module" do
      {tmp, dep} =
        create_fixture(:var_test3, """
        defmodule Evil do
          def run do
            m = :os
            m.cmd(~c"whoami")
          end
        end
        """)

      findings = SystemExec.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :system_exec))
    end

    test "detects File.write! through variable-bound File" do
      {tmp, dep} =
        create_fixture(:var_test4, """
        defmodule Evil do
          def run do
            f = File
            f.write!("/tmp/evil", "payload")
          end
        end
        """)

      findings = FileAccess.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.category == :file_access))
    end
  end

  # ---------------------------------------------------------------------------
  # Combined evasion techniques
  # ---------------------------------------------------------------------------

  describe "combined evasion" do
    test "detects aliased + imported in same module" do
      {tmp, dep} =
        create_fixture(:combo_test, ~S"""
        defmodule Evil do
          alias Code, as: C
          import System

          def steal do
            creds = get_env()
            C.eval_string("send_home(#{inspect(creds)})")
          end
        end
        """)

      code_findings = CodeEval.run(dep, tmp, %{})
      env_findings = EnvAccess.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(code_findings) > 0
      assert length(env_findings) > 0
    end

    test "compile-time alias is still classified as critical" do
      {tmp, dep} =
        create_fixture(:ct_alias, """
        defmodule Evil do
          alias System, as: S
          S.cmd("whoami", [])
        end
        """)

      findings = SystemExec.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(findings) > 0
      assert Enum.any?(findings, &(&1.compile_time? == true))
      assert Enum.any?(findings, &(&1.severity == :critical))
    end

    test "alias + variable binding in same module" do
      {tmp, dep} =
        create_fixture(:alias_var_combo, """
        defmodule Evil do
          alias Code, as: C

          def run do
            s = System
            s.cmd("whoami", [])
            C.eval_string("dangerous")
          end
        end
        """)

      exec_findings = SystemExec.run(dep, tmp, %{})
      eval_findings = CodeEval.run(dep, tmp, %{})
      cleanup(tmp)

      assert length(exec_findings) > 0
      assert length(eval_findings) > 0
    end
  end

  # ---------------------------------------------------------------------------
  # No false positives
  # ---------------------------------------------------------------------------

  describe "no false positives" do
    test "normal unrelated function calls produce no findings" do
      {tmp, dep} =
        create_fixture(:benign, """
        defmodule Safe do
          import Enum
          def run, do: map([1, 2, 3], & &1 * 2)
        end
        """)

      findings =
        SystemExec.run(dep, tmp, %{}) ++
          CodeEval.run(dep, tmp, %{}) ++
          EnvAccess.run(dep, tmp, %{})

      cleanup(tmp)

      assert findings == []
    end

    test "variable not bound to dangerous module produces no findings" do
      {tmp, dep} =
        create_fixture(:safe_var, """
        defmodule Safe do
          def run do
            mod = MyApp.Utils
            mod.do_stuff()
          end
        end
        """)

      findings = SystemExec.run(dep, tmp, %{}) ++ CodeEval.run(dep, tmp, %{})
      cleanup(tmp)

      assert findings == []
    end

    test "alias to non-dangerous module produces no findings" do
      {tmp, dep} =
        create_fixture(:safe_alias, """
        defmodule Safe do
          alias MyApp.Helpers, as: H
          def run, do: H.do_stuff()
        end
        """)

      findings =
        SystemExec.run(dep, tmp, %{}) ++
          CodeEval.run(dep, tmp, %{}) ++
          FileAccess.run(dep, tmp, %{})

      cleanup(tmp)

      assert findings == []
    end
  end
end
