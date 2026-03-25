defmodule VetService.Attestation.AttestationAPI do
  @moduledoc """
  Public API for community attestations.

  Allows community members to submit attestations confirming
  (or disputing) scan findings, and to query current consensus.
  """

  alias VetService.Events.CommunityAttestationSubmitted
  alias VetService.Attestation.Consensus

  @doc """
  Submit a new attestation for a package version's findings.

  Returns the event that would be persisted.
  """
  @spec submit(String.t(), String.t(), String.t()) :: {:ok, struct()}
  def submit(package_name, version, findings_hash) do
    event = %CommunityAttestationSubmitted{
      package_name: package_name,
      version: version,
      attestation_id: generate_id(),
      findings_hash: findings_hash,
      submitter_id: "anonymous",
      submitted_at: DateTime.utc_now()
    }

    {:ok, event}
  end

  @doc """
  Query the current attestation consensus for a package version.

  In production this reads from the AttestationSummary projection.
  For now returns a computed consensus from the provided attestations.
  """
  @spec query(String.t(), String.t()) :: {:ok, map()}
  def query(package_name, version) do
    # Placeholder: in production, read from AttestationSummary projection
    {:ok,
     %{
       package_name: package_name,
       version: version,
       consensus_hash: nil,
       agreement_ratio: 0.0,
       total_attestations: 0
     }}
  end

  @doc """
  Compute consensus from a list of attestation events.
  Delegates to Consensus module.
  """
  @spec compute_consensus([struct()]) :: map()
  def compute_consensus(attestations) do
    Consensus.compute(attestations)
  end

  defp generate_id do
    Base.hex_encode32(:crypto.strong_rand_bytes(10), case: :lower, padding: false)
  end
end
