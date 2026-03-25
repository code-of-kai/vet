defmodule VetService.Commands.SuppressFinding do
  @moduledoc "Command to suppress a specific finding for a package version."

  defstruct [:package_name, :version, :finding_id, :reason, :suppressed_by]
end
