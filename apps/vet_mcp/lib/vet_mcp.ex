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
  Register all Vet tools with Tidewave by injecting into its ETS tool table.

  Call this after Tidewave has started (e.g., in your Application.start/2).
  Returns :ok or {:error, reason}.
  """
  def register do
    if Code.ensure_loaded?(Tidewave.MCP.Server) do
      try do
        {existing_tools, existing_dispatch} = Tidewave.MCP.Server.tools_and_dispatch()

        # Guard against double-registration
        already_registered? = Enum.any?(existing_tools, fn t -> t.name == "vet_scan_dependencies" end)

        if already_registered? do
          throw(:already_registered)
        end

        vet_tools = tidewave_tools()
        vet_dispatch = Map.new(vet_tools, fn tool -> {tool.name, tool.callback} end)

        merged_tools = existing_tools ++ vet_tools
        merged_dispatch = Map.merge(existing_dispatch, vet_dispatch)

        # The :tidewave_tools ETS table is owned by the Tidewave.MCP supervisor.
        # Only the owner can write. We ask the owner to do the insert for us.
        owner_pid = :ets.info(:tidewave_tools, :owner)

        ref = make_ref()
        caller = self()

        # Execute the insert in the owner's context via :sys.replace_state,
        # which runs a callback in the target process. We use it as a side-effect
        # vehicle — the state itself is returned unchanged.
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
      rescue
        e -> {:error, Exception.message(e)}
      catch
        :already_registered -> :ok
      end
    else
      {:error, :tidewave_not_loaded}
    end
  end
end
