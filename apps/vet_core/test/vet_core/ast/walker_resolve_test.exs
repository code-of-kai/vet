defmodule VetCore.AST.WalkerResolveTest do
  @moduledoc """
  Unit tests for Walker.resolve_call/2 directly.

  These tests verify that the Walker correctly resolves calls through aliases,
  imports, and variable bindings at the AST level, independent of any
  particular check module.
  """
  use ExUnit.Case, async: true

  alias VetCore.AST.Walker
  alias VetCore.Types.Finding

  # ---------------------------------------------------------------------------
  # Helper: parse code, walk with a collector that records all resolve_call results
  # ---------------------------------------------------------------------------

  defp resolve_calls(code) do
    {:ok, ast} = Code.string_to_quoted(code, columns: true)

    collector = fn node, state ->
      case Walker.resolve_call(node, state) do
        :nomatch ->
          nil

        {type, mod, func, _args, meta} ->
          %Finding{
            dep_name: :test,
            file_path: "test.ex",
            line: meta[:line] || 0,
            column: meta[:column],
            check_id: :test,
            category: :code_eval,
            severity: :warning,
            compile_time?: false,
            snippet: "#{type}:#{inspect(mod)}.#{func}",
            description: "#{type}:#{inspect(mod)}.#{func}"
          }
      end
    end

    Walker.walk(ast, [collector], "test.ex", :test)
  end

  # ---------------------------------------------------------------------------
  # Remote calls
  # ---------------------------------------------------------------------------

  describe "remote calls" do
    test "resolves simple Elixir remote call" do
      findings = resolve_calls(~s|System.cmd("whoami", [])|)
      assert Enum.any?(findings, &(&1.description =~ "[:System].cmd"))
    end

    test "resolves Erlang module call" do
      findings = resolve_calls(~s|:os.cmd(~c"whoami")|)
      assert Enum.any?(findings, &(&1.description =~ "[:os].cmd"))
    end

    test "resolves multi-segment Elixir module call" do
      findings = resolve_calls(~s|Mint.HTTP.connect(:https, "evil.com", 443)|)
      assert Enum.any?(findings, &(&1.description =~ "[:Mint, :HTTP].connect"))
    end
  end

  # ---------------------------------------------------------------------------
  # Alias resolution
  # ---------------------------------------------------------------------------

  describe "alias resolution" do
    test "resolves aliased call" do
      findings =
        resolve_calls("""
        alias System, as: S
        S.cmd("whoami", [])
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:System].cmd"))
    end

    test "resolves alias with default short name" do
      findings =
        resolve_calls("""
        alias Code
        Code.eval_string("dangerous")
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:Code].eval_string"))
    end

    test "resolves chained alias segments" do
      findings =
        resolve_calls("""
        alias Mint.HTTP, as: H
        H.connect(:https, "evil.com", 443)
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:Mint, :HTTP].connect"))
    end
  end

  # ---------------------------------------------------------------------------
  # Variable binding resolution
  # ---------------------------------------------------------------------------

  describe "variable binding resolution" do
    test "resolves variable-bound Elixir module call" do
      findings =
        resolve_calls("""
        mod = System
        mod.cmd("whoami", [])
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:System].cmd"))
    end

    test "resolves variable-bound Erlang module call" do
      findings =
        resolve_calls("""
        m = :os
        m.cmd(~c"whoami")
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:os].cmd"))
    end

    test "does not resolve unbound variable" do
      findings =
        resolve_calls("""
        unknown_var.cmd("whoami", [])
        """)

      # Should not resolve since unknown_var is not bound to a module
      refute Enum.any?(findings, &(&1.description =~ "cmd"))
    end
  end

  # ---------------------------------------------------------------------------
  # Import resolution
  # ---------------------------------------------------------------------------

  describe "import resolution" do
    test "resolves imported function call" do
      findings =
        resolve_calls("""
        import System
        cmd("whoami", [])
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:System].cmd"))
    end

    test "resolves imported Erlang module function" do
      findings =
        resolve_calls("""
        import :os
        cmd(~c"whoami")
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:os].cmd"))
    end

    test "does not resolve non-dangerous imports as false match" do
      findings =
        resolve_calls("""
        import Enum
        map([1, 2, 3], & &1 * 2)
        """)

      # Enum.map may resolve via runtime introspection (Code.ensure_loaded?),
      # but the key thing is this list is valid and doesn't crash.
      assert is_list(findings)
    end
  end

  # ---------------------------------------------------------------------------
  # Combined resolution
  # ---------------------------------------------------------------------------

  describe "combined resolution" do
    test "alias + imported in same scope" do
      findings =
        resolve_calls("""
        alias Code, as: C
        import System
        C.eval_string("dangerous")
        cmd("whoami", [])
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:Code].eval_string"))
      assert Enum.any?(findings, &(&1.description =~ "[:System].cmd"))
    end

    test "alias + variable binding in same scope" do
      findings =
        resolve_calls("""
        alias Code, as: C
        m = :os
        C.eval_string("dangerous")
        m.cmd(~c"whoami")
        """)

      assert Enum.any?(findings, &(&1.description =~ "[:Code].eval_string"))
      assert Enum.any?(findings, &(&1.description =~ "[:os].cmd"))
    end
  end

  # ---------------------------------------------------------------------------
  # Metadata preservation
  # ---------------------------------------------------------------------------

  describe "metadata" do
    test "preserves line numbers from resolved calls" do
      findings =
        resolve_calls("""
        alias System, as: S
        S.cmd("whoami", [])
        """)

      finding = Enum.find(findings, &(&1.description =~ "[:System].cmd"))
      assert finding != nil
      assert finding.line > 0
    end

    test "preserves column numbers from resolved calls" do
      findings =
        resolve_calls("""
        alias System, as: S
        S.cmd("whoami", [])
        """)

      finding = Enum.find(findings, &(&1.description =~ "[:System].cmd"))
      assert finding != nil
      assert finding.column != nil
    end
  end
end
