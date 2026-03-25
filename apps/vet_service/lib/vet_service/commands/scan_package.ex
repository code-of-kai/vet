defmodule VetService.Commands.ScanPackage do
  @moduledoc "Command to initiate a scan of a package version."

  defstruct [:package_name, :version, :scan_id, :requested_at]
end
