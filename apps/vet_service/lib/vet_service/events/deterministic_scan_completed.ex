defmodule VetService.Events.DeterministicScanCompleted do
  @moduledoc "Emitted when a deterministic (rule-based) scan finishes."

  @derive Jason.Encoder
  defstruct [:package_name, :version, :scan_id, :findings, :risk_score, :scanned_at]
end
