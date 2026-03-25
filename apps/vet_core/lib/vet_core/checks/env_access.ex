defmodule VetCore.Checks.EnvAccess do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :env_access
  @base_severity :warning

  @sensitive_patterns ~w(SECRET KEY TOKEN PASSWORD CREDENTIAL AWS_ GITHUB_ DATABASE_URL)

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    with {_type, [:System] = _module, func, args, meta}
         when func in [:get_env, :fetch_env, :fetch_env!] <-
           Walker.resolve_call(node, state) do
      classify_env_call(func, args, meta, state, dep_name, source)
    else
      _ -> nil
    end
  end

  defp classify_env_call(:get_env, [], meta, state, dep_name, source) do
    # System.get_env/0 — dumps all env vars
    # Exclude function captures like &System.get_env/1 which also have empty args
    if meta[:no_parens] do
      nil
    else
      build_finding(
        "Call to System.get_env/0 — dumps all environment variables",
        :critical,
        meta,
        state,
        dep_name,
        source
      )
    end
  end

  defp classify_env_call(:get_env, [env_var | _], meta, state, dep_name, source)
       when is_binary(env_var) do
    if sensitive_env_var?(env_var) do
      build_finding(
        "Call to System.get_env(\"#{env_var}\") — accesses a sensitive environment variable",
        :critical,
        meta,
        state,
        dep_name,
        source
      )
    else
      build_finding(
        "Call to System.get_env(\"#{env_var}\") — reads an environment variable",
        nil,
        meta,
        state,
        dep_name,
        source
      )
    end
  end

  defp classify_env_call(:get_env, [_ | _], meta, state, dep_name, source) do
    build_finding(
      "Call to System.get_env/1 — reads an environment variable",
      nil,
      meta,
      state,
      dep_name,
      source
    )
  end

  defp classify_env_call(func, [env_var | _], meta, state, dep_name, source)
       when func in [:fetch_env, :fetch_env!] do
    if is_binary(env_var) and sensitive_env_var?(env_var) do
      build_finding(
        "Call to System.#{func}(\"#{env_var}\") — accesses a sensitive environment variable",
        :critical,
        meta,
        state,
        dep_name,
        source
      )
    else
      build_finding(
        "Call to System.#{func} — reads an environment variable",
        nil,
        meta,
        state,
        dep_name,
        source
      )
    end
  end

  defp classify_env_call(_func, _args, _meta, _state, _dep_name, _source), do: nil

  defp build_finding(description, severity_override, meta, state, dep_name, source) do
    is_ct = FileHelper.compile_time?(state.context_stack)

    severity =
      cond do
        severity_override == :critical -> :critical
        is_ct -> :critical
        true -> @base_severity
      end

    line = meta[:line] || 0

    %Finding{
      dep_name: dep_name,
      file_path: state.file_path,
      line: line,
      column: meta[:column],
      check_id: :env_access,
      category: @category,
      severity: severity,
      compile_time?: is_ct,
      snippet: FileHelper.snippet(source, line),
      description: description
    }
  end

  defp sensitive_env_var?(name) do
    upper = String.upcase(name)
    Enum.any?(@sensitive_patterns, &String.contains?(upper, &1))
  end
end
