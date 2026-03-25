defmodule VetService.Events.FindingSuppressed do
  @moduledoc "Emitted when a finding is suppressed (acknowledged as acceptable)."

  @derive Jason.Encoder
  defstruct [:package_name, :version, :finding_id, :reason, :suppressed_by]
end
