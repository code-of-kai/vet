defmodule VetService.Attestation.AttestationAPI do
  @moduledoc """
  Public API for community attestations.

  Allows community members to submit attestations confirming
  (or disputing) scan findings, and to query current consensus.
  """

  alias VetService.Attestation.Consensus

  @doc """
  Submit a new attestation for a package version's findings.

  Stores the attestation and returns `:ok`.
  """
  @spec submit(String.t(), String.t(), String.t()) :: :ok
  def submit(package_name, version, findings_hash) do
    attestation = %{
      attestation_id: generate_id(),
      findings_hash: findings_hash,
      submitter_id: "anonymous",
      submitted_at: DateTime.utc_now()
    }

    VetService.submit_attestation(package_name, version, attestation)
  end

  @doc """
  Query the current attestation consensus for a package version.

  Reads attestations from the Store and computes consensus.
  """
  @spec query(String.t(), String.t()) :: map()
  def query(package_name, version) do
    consensus = VetService.get_consensus(package_name, version)

    Map.merge(consensus, %{
      package_name: package_name,
      version: version
    })
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
