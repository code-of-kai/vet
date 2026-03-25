defmodule VetMcp do
  @moduledoc """
  MCP tool integration for Vet.

  Provides security scanning tools that can be registered with Tidewave
  or any MCP-compatible tool server.
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

  Each entry contains the tool name, description, input schema, and the
  module that implements it.
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

  @doc """
  Register all Vet tools with a Tidewave-compatible tool server.

  When Tidewave is available, this can be called during application startup
  to make the tools available via MCP. Returns :ok or {:error, reason}.
  """
  def register do
    definitions = tool_definitions()

    if Code.ensure_loaded?(Tidewave) do
      Enum.each(definitions, fn def ->
        apply(Tidewave, :register_tool, [def.name, def.module])
      end)

      :ok
    else
      {:ok, definitions}
    end
  end
end
