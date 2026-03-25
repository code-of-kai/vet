defmodule VetCore.Checks.NetworkAccess do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :network_access
  @base_severity :warning

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
        {description, line, column} ->
          is_ct = FileHelper.compile_time?(ctx)
          severity = if is_ct, do: :critical, else: @base_severity

          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line,
            column: column,
            check_id: :network_access,
            category: @category,
            severity: severity,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description: description
          }]
      end
    end)
  end

  # :httpc.request
  defp match_pattern({{:., _, [:httpc, :request]}, meta, _args}) do
    {"Call to :httpc.request — makes an HTTP request via Erlang's httpc",
     meta[:line] || 0, meta[:column]}
  end

  # :gen_tcp.connect
  defp match_pattern({{:., _, [:gen_tcp, :connect]}, meta, _args}) do
    {"Call to :gen_tcp.connect — opens a raw TCP connection",
     meta[:line] || 0, meta[:column]}
  end

  # :ssl.connect
  defp match_pattern({{:., _, [:ssl, :connect]}, meta, _args}) do
    {"Call to :ssl.connect — opens an SSL/TLS connection",
     meta[:line] || 0, meta[:column]}
  end

  # Req.*
  defp match_pattern({{:., _, [{:__aliases__, _, [:Req]}, func]}, meta, _args}) do
    {"Call to Req.#{func} — HTTP client library call",
     meta[:line] || 0, meta[:column]}
  end

  # HTTPoison.*
  defp match_pattern({{:., _, [{:__aliases__, _, [:HTTPoison]}, func]}, meta, _args}) do
    {"Call to HTTPoison.#{func} — HTTP client library call",
     meta[:line] || 0, meta[:column]}
  end

  # Finch.*
  defp match_pattern({{:., _, [{:__aliases__, _, [:Finch]}, func]}, meta, _args}) do
    {"Call to Finch.#{func} — HTTP client library call",
     meta[:line] || 0, meta[:column]}
  end

  # Mint.HTTP.*
  defp match_pattern({{:., _, [{:__aliases__, _, [:Mint, :HTTP]}, func]}, meta, _args}) do
    {"Call to Mint.HTTP.#{func} — low-level HTTP client call",
     meta[:line] || 0, meta[:column]}
  end

  defp match_pattern(_), do: nil
end
