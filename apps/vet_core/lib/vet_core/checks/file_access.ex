defmodule VetCore.Checks.FileAccess do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :file_access
  @base_severity :warning

  @sensitive_paths ~w(~/.ssh ~/.aws ~/.kube ~/.gnupg ~/.config /etc/passwd /etc/shadow)

  @file_functions [:read!, :write!, :stream!, :rm, :rm_rf, :read, :write, :cp, :cp_r]

  @impl true
  def init(opts), do: opts

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      scan_ast(ast, dep_name, file_path, source)
    end)
  end

  defp scan_ast(ast, dep_name, file_path, source) do
    FileHelper.walk_ast(ast, fn node, ctx ->
      case match_pattern(node) do
        nil -> []
        {description, line, column, sensitive?} ->
          is_ct = FileHelper.compile_time?(ctx)
          severity = cond do
            sensitive? -> :critical
            is_ct -> :critical
            true -> @base_severity
          end

          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line,
            column: column,
            check_id: :file_access,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  defp match_pattern({{:., _, [{:__aliases__, _, [:File]}, func]}, meta, args})
       when func in @file_functions do
    sensitive? = args_contain_sensitive_path?(args)

    desc =
      if sensitive? do
        "Call to File.#{func} accessing a sensitive path — potential credential exfiltration"
      else
        "Call to File.#{func} — filesystem access"
      end

    {desc, meta[:line] || 0, meta[:column], sensitive?}
  end

  defp match_pattern(_), do: nil

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
