defmodule VetService.Aggregates.PackageVersion do
  @moduledoc """
  Aggregate root for a specific package version.

  Tracks the full scan lifecycle: deterministic scan, LLM review,
  community attestations, suppressions, and composite risk score.
  """

  defstruct [
    :package_name,
    :version,
    :current_scan,
    :risk_score,
    attestations: [],
    suppressions: []
  ]

  alias VetService.Aggregates.PackageVersion
  alias VetService.Commands.{ScanPackage, SubmitAttestation, SuppressFinding}

  alias VetService.Events.{
    DeterministicScanCompleted,
    CommunityAttestationSubmitted,
    FindingSuppressed
  }

  # --- Command handling ---

  def execute(%PackageVersion{current_scan: nil}, %ScanPackage{} = cmd) do
    %DeterministicScanCompleted{
      package_name: cmd.package_name,
      version: cmd.version,
      scan_id: cmd.scan_id,
      findings: [],
      risk_score: 0,
      scanned_at: DateTime.utc_now()
    }
  end

  def execute(%PackageVersion{}, %ScanPackage{} = cmd) do
    # Re-scan: always allowed
    %DeterministicScanCompleted{
      package_name: cmd.package_name,
      version: cmd.version,
      scan_id: cmd.scan_id,
      findings: [],
      risk_score: 0,
      scanned_at: DateTime.utc_now()
    }
  end

  def execute(%PackageVersion{}, %SubmitAttestation{} = cmd) do
    %CommunityAttestationSubmitted{
      package_name: cmd.package_name,
      version: cmd.version,
      attestation_id: cmd.attestation_id,
      findings_hash: cmd.findings_hash,
      submitter_id: cmd.submitter_id,
      submitted_at: cmd.submitted_at || DateTime.utc_now()
    }
  end

  def execute(%PackageVersion{suppressions: suppressions}, %SuppressFinding{} = cmd) do
    already_suppressed = Enum.any?(suppressions, fn s -> s.finding_id == cmd.finding_id end)

    if already_suppressed do
      {:error, :already_suppressed}
    else
      %FindingSuppressed{
        package_name: cmd.package_name,
        version: cmd.version,
        finding_id: cmd.finding_id,
        reason: cmd.reason,
        suppressed_by: cmd.suppressed_by
      }
    end
  end

  # --- Event application ---

  def apply(%PackageVersion{} = state, %DeterministicScanCompleted{} = event) do
    %PackageVersion{
      state
      | package_name: event.package_name,
        version: event.version,
        current_scan: %{
          scan_id: event.scan_id,
          findings: event.findings,
          risk_score: event.risk_score,
          scanned_at: event.scanned_at
        },
        risk_score: event.risk_score
    }
  end

  def apply(%PackageVersion{} = state, %CommunityAttestationSubmitted{} = event) do
    attestation = %{
      attestation_id: event.attestation_id,
      findings_hash: event.findings_hash,
      submitter_id: event.submitter_id,
      submitted_at: event.submitted_at
    }

    %PackageVersion{state | attestations: state.attestations ++ [attestation]}
  end

  def apply(%PackageVersion{} = state, %FindingSuppressed{} = event) do
    suppression = %{
      finding_id: event.finding_id,
      reason: event.reason,
      suppressed_by: event.suppressed_by
    }

    %PackageVersion{state | suppressions: state.suppressions ++ [suppression]}
  end

  # Catch-all for events that don't change aggregate state
  def apply(%PackageVersion{} = state, _event), do: state
end
