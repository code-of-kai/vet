defmodule VetMcp.Tools.CheckPackage do
  @moduledoc false
  @behaviour VetMcp.Tool

  @impl true
  def name, do: "vet_check_package"

  @impl true
  def description do
    "Check a specific Hex package for security concerns before adding it as a dependency. " <>
      "Useful when an AI assistant is about to suggest adding a dependency."
  end

  @impl true
  def schema do
    %{
      type: "object",
      required: ["package"],
      properties: %{
        package: %{
          type: "string",
          description: "Package name on hex.pm"
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
    package_atom =
      try do
        String.to_existing_atom(name)
      rescue
        ArgumentError -> nil
      end

    if is_nil(package_atom) do
      {:error, "Unknown package: #{name}. Package must exist in deps/."}
    else
      execute_check(package_atom, name, params)
    end
  end

  def execute(_params, _context) do
    {:error, "Missing required parameter: package"}
  end

  defp execute_check(package_atom, name, params) do
    metadata =
      case VetCore.Metadata.HexChecker.fetch_metadata(package_atom) do
        {:ok, meta} -> meta
        {:error, _} -> %VetCore.Types.HexMetadata{}
      end

    version = Map.get(params, "version", metadata.latest_version)

    dep = %VetCore.Types.Dependency{
      name: package_atom,
      source: :hex,
      version: version
    }

    typosquat_findings = VetCore.Metadata.TyposquatDetector.check_dep(dep)

    result = %{
      package: name,
      version: version,
      metadata: %{
        downloads: metadata.downloads,
        latest_version: metadata.latest_version,
        latest_release_date:
          metadata.latest_release_date && DateTime.to_iso8601(metadata.latest_release_date),
        owner_count: metadata.owner_count,
        description: metadata.description,
        retired: metadata.retired?
      },
      typosquat_warnings:
        Enum.map(typosquat_findings, fn f -> f.description end),
      assessment: assess(metadata, typosquat_findings)
    }

    {:ok, Jason.encode!(result, pretty: true)}
  end

  defp assess(metadata, typosquat_findings) do
    warnings = []

    warnings =
      if metadata.downloads && metadata.downloads < 1000,
        do: ["Low download count (#{metadata.downloads})" | warnings],
        else: warnings

    warnings =
      if metadata.owner_count == 1,
        do: ["Single package owner" | warnings],
        else: warnings

    warnings =
      if metadata.retired?,
        do: ["Package is retired" | warnings],
        else: warnings

    warnings =
      if metadata.description in [nil, ""],
        do: ["No package description" | warnings],
        else: warnings

    warnings =
      if typosquat_findings != [],
        do: ["Possible typosquat" | warnings],
        else: warnings

    warnings =
      case metadata.latest_release_date do
        %DateTime{} = dt ->
          days_ago = DateTime.diff(DateTime.utc_now(), dt, :day)

          if days_ago < 7,
            do: ["Latest version published #{days_ago} days ago" | warnings],
            else: warnings

        _ ->
          warnings
      end

    case length(warnings) do
      0 -> "No concerns identified."
      _ -> "Warnings: " <> Enum.join(warnings, "; ")
    end
  end
end
