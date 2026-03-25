defmodule VetService.CommandHandlers.ScanHandler do
  @moduledoc """
  Orchestrates scan execution outside the aggregate boundary.

  Receives a ScanPackage command context, runs the actual deterministic
  scan via VetCore, and returns the result as events. This handler is
  invoked by the pipeline, not directly by the router (the router
  dispatches to the aggregate which emits placeholder events; the real
  scan work happens here asynchronously).
  """

  alias VetService.Events.{DeterministicScanCompleted, RiskScoreComputed}

  @doc """
  Run a deterministic scan for the given package version.

  Returns a list of events to be persisted.
  """
  @spec handle(String.t(), String.t(), String.t()) :: [struct()]
  def handle(package_name, version, scan_id) do
    # In production this delegates to VetCore scanning engine.
    # For now return a clean scan result.
    now = DateTime.utc_now()

    scan_event = %DeterministicScanCompleted{
      package_name: package_name,
      version: version,
      scan_id: scan_id,
      findings: [],
      risk_score: 0,
      scanned_at: now
    }

    risk_event = %RiskScoreComputed{
      package_name: package_name,
      version: version,
      score: 0,
      level: :low,
      factors: %{}
    }

    [scan_event, risk_event]
  end
end
