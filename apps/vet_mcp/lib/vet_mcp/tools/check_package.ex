defmodule VetMcp.Tools.CheckPackage do
  @moduledoc false

  def name, do: "check_package"

  def description do
    "Check a specific Hex package for security issues before adding it as a dependency. " <>
      "Fetches metadata from hex.pm and checks for typosquatting, low downloads, and suspicious signals."
  end

  def parameters do
    %{
      type: "object",
      required: ["package_name"],
      properties: %{
        package_name: %{
          type: "string",
          description: "Name of the Hex package to check."
        }
      }
    }
  end

  def run(%{"package_name" => name}) do
    metadata = VetCore.Metadata.HexChecker.fetch_metadata(String.to_atom(name))

    dep = %VetCore.Types.Dependency{
      name: String.to_atom(name),
      source: :hex,
      version: metadata.latest_version
    }

    typosquat_findings = VetCore.Metadata.TyposquatDetector.check_dep(dep)

    result = %{
      package: name,
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
