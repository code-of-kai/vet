defmodule VetMcp.Tools.CheckPackage do
  @moduledoc false
  @behaviour VetMcp.Tool

  @impl true
  def name, do: "vet_check_package"

  @impl true
  def description do
    "Check a Hex package for security concerns BEFORE adding it as a dependency. " <>
      "Detects phantom packages (don't exist on hex.pm), typosquats, slopsquatting targets, " <>
      "and low-adoption packages. Does not require the package to be installed."
  end

  @impl true
  def schema do
    %{
      type: "object",
      required: ["package"],
      properties: %{
        package: %{
          type: "string",
          description: "Package name to check (does not need to be installed)"
        },
        version: %{
          type: "string",
          description: "Specific version to check (optional, defaults to latest)"
        }
      }
    }
  end

  @impl true
  def execute(%{"package" => name} = params, _context) do
    case VetCore.PreInstallCheck.validate_package_name(name) do
      {:ok, package_atom} ->
        result = VetCore.PreInstallCheck.check_package(package_atom)

        version = Map.get(params, "version", result.metadata && result.metadata.latest_version)

        output = %{
          package: name,
          version: version,
          phantom: result.phantom?,
          metadata:
            if result.metadata do
              %{
                downloads: result.metadata.downloads,
                latest_version: result.metadata.latest_version,
                latest_release_date:
                  result.metadata.latest_release_date &&
                    DateTime.to_iso8601(result.metadata.latest_release_date),
                owner_count: result.metadata.owner_count,
                description: result.metadata.description,
                retired: result.metadata.retired?
              }
            else
              nil
            end,
          typosquat_warnings: result.typosquat_warnings,
          assessment: result.assessment
        }

        {:ok, Jason.encode!(output, pretty: true)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def execute(_params, _context) do
    {:error, "Missing required parameter: package"}
  end
end
