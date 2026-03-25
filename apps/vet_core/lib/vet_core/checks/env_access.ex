defmodule VetCore.Checks.EnvAccess do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :env_access
  @base_severity :warning

  @sensitive_patterns ~w(SECRET KEY TOKEN PASSWORD CREDENTIAL AWS_ GITHUB_ DATABASE_URL)

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
        {description, line, column, severity_override} ->
          is_ct = FileHelper.compile_time?(ctx)
          severity = cond do
            severity_override == :critical -> :critical
            is_ct -> :critical
            true -> @base_severity
          end

          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line,
            column: column,
            check_id: :env_access,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # System.get_env/0 — no arguments, dumps all env vars
  # Exclude function captures like &System.get_env/1 which also have empty args
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, :get_env]}, meta, []}) do
    if meta[:no_parens] do
      nil
    else
      {"Call to System.get_env/0 — dumps all environment variables",
       meta[:line] || 0, meta[:column], :critical}
    end
  end

  # System.get_env/1 with a string literal argument
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, :get_env]}, meta, [env_var | _]})
       when is_binary(env_var) do
    if sensitive_env_var?(env_var) do
      {"Call to System.get_env(\"#{env_var}\") — accesses a sensitive environment variable",
       meta[:line] || 0, meta[:column], :critical}
    else
      {"Call to System.get_env(\"#{env_var}\") — reads an environment variable",
       meta[:line] || 0, meta[:column], nil}
    end
  end

  # System.get_env/1 with a non-literal argument
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, :get_env]}, meta, [_ | _]}) do
    {"Call to System.get_env/1 — reads an environment variable",
     meta[:line] || 0, meta[:column], nil}
  end

  # System.fetch_env/1 and System.fetch_env!/1
  defp match_pattern({{:., _, [{:__aliases__, _, [:System]}, func]}, meta, [env_var | _]})
       when func in [:fetch_env, :fetch_env!] do
    if is_binary(env_var) and sensitive_env_var?(env_var) do
      {"Call to System.#{func}(\"#{env_var}\") — accesses a sensitive environment variable",
       meta[:line] || 0, meta[:column], :critical}
    else
      {"Call to System.#{func} — reads an environment variable",
       meta[:line] || 0, meta[:column], nil}
    end
  end

  defp match_pattern(_), do: nil

  defp sensitive_env_var?(name) do
    upper = String.upcase(name)
    Enum.any?(@sensitive_patterns, &String.contains?(upper, &1))
  end
end
