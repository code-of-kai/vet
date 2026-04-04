defmodule VetMcp.Tools.DiffPackageVersions do
  @moduledoc false
  @behaviour VetMcp.Tool

  @impl true
  def name, do: "vet_diff_versions"

  @impl true
  def description do
    "Compare two versions of a package to detect suspicious changes, " <>
      "new security findings, or pattern profile shifts."
  end

  @impl true
  def schema do
    %{
      type: "object",
      required: ["package", "from_version", "to_version"],
      properties: %{
        package: %{
          type: "string",
          description: "Package name on hex.pm"
        },
        from_version: %{
          type: "string",
          description: "Previous version to compare from"
        },
        to_version: %{
          type: "string",
          description: "New version to compare to"
        }
      }
    }
  end

  @impl true
  def execute(
        %{"package" => name, "from_version" => from_ver, "to_version" => to_ver},
        _context
      ) do
    case VetCore.PreInstallCheck.validate_package_name(name) do
      {:ok, package_atom} ->
        execute_diff(package_atom, name, from_ver, to_ver)

      {:error, reason} ->
        {:error, reason}
    end
  end

  def execute(_params, _context) do
    {:error, "Missing required parameters: package, from_version, to_version"}
  end

  defp execute_diff(package_atom, name, from_ver, to_ver) do
    case VetCore.VersionDiff.diff(File.cwd!(), package_atom, from_ver, to_ver) do
      {:ok, diff} ->
        {suspicious?, signals} = VetCore.VersionDiff.suspicious_delta?(diff)

        result = %{
          package: name,
          from_version: from_ver,
          to_version: to_ver,
          new_files: diff.new_files,
          removed_files: diff.removed_files,
          modified_files: diff.modified_files,
          new_findings: length(diff.new_findings),
          resolved_findings: length(diff.resolved_findings),
          profile_shift: diff.profile_shift,
          suspicious: suspicious?,
          signals: Enum.map(signals, &to_string/1)
        }

        {:ok, Jason.encode!(result, pretty: true)}

      {:error, :version_unavailable} ->
        {:error, "One or both versions of #{name} could not be fetched. " <>
          "Ensure the package and versions exist on hex.pm."}

      {:error, reason} ->
        {:error, "Version diff failed: #{inspect(reason)}"}
    end
  end
end
