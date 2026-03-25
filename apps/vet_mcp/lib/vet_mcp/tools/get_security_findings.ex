defmodule VetMcp.Tools.GetSecurityFindings do
  @moduledoc false

  def name, do: "get_security_findings"

  def description do
    "Scan the current project's dependencies for supply chain attack indicators. " <>
      "Returns risk scores and findings for each dependency."
  end

  def parameters do
    %{
      type: "object",
      properties: %{
        project_path: %{
          type: "string",
          description: "Path to the Elixir project to scan. Defaults to current directory."
        }
      }
    }
  end

  def run(%{"project_path" => path}) do
    run_scan(path)
  end

  def run(_params) do
    run_scan(File.cwd!())
  end

  defp run_scan(path) do
    case VetCore.scan(path, skip_hex: false) do
      {:ok, report} ->
        {:ok, VetReporter.Json.encode(report)}

      {:error, reason} ->
        {:error, "Scan failed: #{inspect(reason)}"}
    end
  end
end
