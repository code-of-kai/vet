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
  Returns Vet tools in Tidewave's native format (maps with :name, :description,
  :inputSchema, :callback).
  """
  def tidewave_tools do
    Enum.map(@tools, fn mod ->
      %{
        name: mod.name(),
        description: mod.description(),
        inputSchema: mod.schema(),
        callback: fn args -> mod.execute(args, %{}) end
      }
    end)
  end

  @doc """
  Register all Vet tools with Tidewave.

  Call this after Tidewave has started (e.g., in your Application.start/2).
  Returns :ok or {:error, reason}.
  """
  def register do
    if Code.ensure_loaded?(Tidewave.MCP.Server) do
      try do
        register_impl()
      rescue
        e -> {:error, Exception.message(e)}
      catch
        :already_registered -> :ok
      end
    else
      {:error, :tidewave_not_loaded}
    end
  end

  # TODO: Switch to the clean API once tidewave-ai/tidewave_phoenix#237 is merged.
  #
  # PR: https://github.com/tidewave-ai/tidewave_phoenix/pull/237
  # Adds Tidewave.MCP.Server.register_tools/1 — a public function for
  # third-party tool registration. When available, this entire function
  # collapses to:
  #
  #     defp register_impl do
  #       Tidewave.MCP.Server.register_tools(tidewave_tools())
  #     end
  #
  # Until then, we inject into the ETS table via :sys.replace_state on
  # the owner process. This works but couples to Tidewave internals
  # (ETS table name, tuple format, owner process identity).
  defp register_impl do
    {existing_tools, _existing_dispatch} = Tidewave.MCP.Server.tools_and_dispatch()

    # Guard against double-registration
    if Enum.any?(existing_tools, fn t -> t.name == "vet_scan_dependencies" end) do
      throw(:already_registered)
    end

    vet_tools = tidewave_tools()
    vet_dispatch = Map.new(vet_tools, fn tool -> {tool.name, tool.callback} end)

    merged_tools = existing_tools ++ vet_tools
    merged_dispatch =
      existing_tools
      |> Map.new(fn tool -> {tool.name, tool.callback} end)
      |> Map.merge(vet_dispatch)

    owner_pid = :ets.info(:tidewave_tools, :owner)
    ref = make_ref()
    caller = self()

    :sys.replace_state(owner_pid, fn state ->
      :ets.insert(:tidewave_tools, {:tools, {merged_tools, merged_dispatch}})
      send(caller, {:vet_registered, ref})
      state
    end)

    receive do
      {:vet_registered, ^ref} -> :ok
    after
      5_000 -> {:error, :registration_timeout}
    end
  end
end
