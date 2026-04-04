defmodule VetMcp do
  @moduledoc """
  MCP tool definitions for Vet.

  These tool modules define the interface for Vet's security scanning
  capabilities. They can be invoked directly via their execute/2 functions,
  or their underlying VetCore functions can be called through Tidewave's
  project_eval tool (see AGENTS.md in the project root).
  """

  @tools [
    VetMcp.Tools.GetSecurityFindings,
    VetMcp.Tools.CheckPackage,
    VetMcp.Tools.DiffPackageVersions
  ]

  @doc """
  Returns the list of available tool modules.
  """
  def tools, do: @tools

  @doc """
  Returns tool definitions in the format expected by MCP tool registration.
  """
  def tool_definitions do
    Enum.map(@tools, fn mod ->
      %{
        name: mod.name(),
        description: mod.description(),
        schema: mod.schema(),
        module: mod
      }
    end)
  end
end
