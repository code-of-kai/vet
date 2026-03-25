defmodule VetMcp.Tools.DiffPackageVersions do
  @moduledoc false

  def name, do: "diff_package_versions"

  def description do
    "Compare two versions of a Hex package for suspicious changes. " <>
      "Shows new findings, resolved findings, and pattern profile shifts between versions."
  end

  def parameters do
    %{
      type: "object",
      required: ["package_name", "old_version", "new_version"],
      properties: %{
        package_name: %{
          type: "string",
          description: "Name of the Hex package."
        },
        old_version: %{
          type: "string",
          description: "Previous version to compare from."
        },
        new_version: %{
          type: "string",
          description: "New version to compare to."
        }
      }
    }
  end

  def run(%{"package_name" => name, "old_version" => old_ver, "new_version" => new_ver}) do
    result = %{
      package: name,
      old_version: old_ver,
      new_version: new_ver,
      status: "Version diffing requires the Vet Service. Use `mix hex.package diff #{name} #{old_ver} #{new_ver}` for now."
    }

    {:ok, Jason.encode!(result, pretty: true)}
  end
end
