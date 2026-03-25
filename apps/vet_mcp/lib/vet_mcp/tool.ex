defmodule VetMcp.Tool do
  @moduledoc """
  Behaviour for Vet MCP tools.

  Each tool exposes a name, description, JSON Schema for input parameters,
  and an execute/2 callback that performs the work.

  This follows the Tidewave MCP tool pattern so tools can be registered
  with Tidewave's tool server when running inside a Phoenix application.
  """

  @callback name() :: String.t()
  @callback description() :: String.t()
  @callback schema() :: map()
  @callback execute(params :: map(), context :: map()) :: {:ok, String.t()} | {:error, String.t()}
end
