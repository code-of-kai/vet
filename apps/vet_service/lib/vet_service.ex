defmodule VetService do
  @moduledoc """
  Service layer for Vet — stores scan results, attestations, and risk timelines.
  """

  alias VetService.Store
  alias VetService.Attestation.Consensus

  @doc "Record a scan result for a package version."
  def record_scan(package_name, version, scan_result) do
    Store.put_scan(package_name, version, scan_result)
    risk_score = Map.get(scan_result, :risk_score) || Map.get(scan_result, "risk_score", 0)
    Store.put_risk_score(package_name, version, risk_score)
    :ok
  end

  @doc "Get the latest scan for a package version."
  def get_scan(package_name, version) do
    Store.get_scan(package_name, version)
  end

  @doc "List all recorded scans, newest first."
  def list_scans do
    Store.list_scans()
  end

  @doc "Submit an attestation for a package version."
  def submit_attestation(package_name, version, attestation) do
    Store.put_attestation(package_name, version, attestation)
    :ok
  end

  @doc "Get consensus for a package version's attestations."
  def get_consensus(package_name, version) do
    attestations = Store.get_attestations(package_name, version)
    Consensus.compute(attestations)
  end

  @doc "Get risk score timeline for a package."
  def get_risk_timeline(package_name) do
    Store.get_risk_timeline(package_name)
  end
end
