defmodule VetCore.Checks.NetworkAccess do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :network_access
  @base_severity :warning

  # Specific function patterns
  @specific_patterns [
    {[:httpc], :request},
    {[:gen_tcp], :connect},
    {[:ssl], :connect}
  ]

  # Module-wildcard patterns — any function on these modules is flagged
  @wildcard_modules %{
    [:Req] => "Req",
    [:HTTPoison] => "HTTPoison",
    [:Finch] => "Finch",
    [:Mint, :HTTP] => "Mint.HTTP"
  }

  @specific_descriptions %{
    {[:httpc], :request} => "Call to :httpc.request — makes an HTTP request via Erlang's httpc",
    {[:gen_tcp], :connect} => "Call to :gen_tcp.connect — opens a raw TCP connection",
    {[:ssl], :connect} => "Call to :ssl.connect — opens an SSL/TLS connection"
  }

  @impl true
  def init(opts), do: opts

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    with {_type, module, func, _args, meta} <- Walker.resolve_call(node, state),
         {true, description} <- classify(module, func) do
      is_ct = FileHelper.compile_time?(state.context_stack)
      severity = if is_ct, do: :critical, else: @base_severity
      line = meta[:line] || 0

      %Finding{
        dep_name: dep_name,
        file_path: state.file_path,
        line: line,
        column: meta[:column],
        check_id: :network_access,
        category: @category,
        severity: severity,
        compile_time?: is_ct,
        snippet: FileHelper.snippet(source, line),
        description: description
      }
    else
      _ -> nil
    end
  end

  defp classify(module, func) do
    cond do
      matches_specific?(module, func) ->
        desc = Map.fetch!(@specific_descriptions, {module, func})
        {true, desc}

      Map.has_key?(@wildcard_modules, module) ->
        lib_name = Map.fetch!(@wildcard_modules, module)

        desc =
          if module == [:Mint, :HTTP] do
            "Call to #{lib_name}.#{func} — low-level HTTP client call"
          else
            "Call to #{lib_name}.#{func} — HTTP client library call"
          end

        {true, desc}

      true ->
        false
    end
  end

  defp matches_specific?(module, func) do
    Enum.any?(@specific_patterns, fn {m, f} -> m == module and f == func end)
  end
end
