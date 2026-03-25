defmodule VetCore.Checks.FileAccess do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :file_access
  @base_severity :warning

  @sensitive_paths ~w(~/.ssh ~/.aws ~/.kube ~/.gnupg ~/.config /etc/passwd /etc/shadow)

  @file_functions [:read!, :write!, :stream!, :rm, :rm_rf, :read, :write, :cp, :cp_r]

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    with {_type, [:File] = _module, func, args, meta} <- Walker.resolve_call(node, state),
         true <- func in @file_functions do
      sensitive? = args_contain_sensitive_path?(args)
      is_ct = FileHelper.compile_time?(state.context_stack)

      severity =
        cond do
          sensitive? -> :critical
          is_ct -> :critical
          true -> @base_severity
        end

      line = meta[:line] || 0

      desc =
        if sensitive? do
          "Call to File.#{func} accessing a sensitive path — potential credential exfiltration"
        else
          "Call to File.#{func} — filesystem access"
        end

      %Finding{
        dep_name: dep_name,
        file_path: state.file_path,
        line: line,
        column: meta[:column],
        check_id: :file_access,
        category: @category,
        severity: severity,
        compile_time?: is_ct,
        snippet: FileHelper.snippet(source, line),
        description: desc
      }
    else
      _ -> nil
    end
  end

  defp args_contain_sensitive_path?(args) do
    Enum.any?(args, fn
      arg when is_binary(arg) ->
        Enum.any?(@sensitive_paths, &String.contains?(arg, &1))

      {:<<>>, _, parts} ->
        parts
        |> Enum.filter(&is_binary/1)
        |> Enum.any?(fn part ->
          Enum.any?(@sensitive_paths, &String.contains?(part, &1))
        end)

      _ ->
        false
    end)
  end
end
