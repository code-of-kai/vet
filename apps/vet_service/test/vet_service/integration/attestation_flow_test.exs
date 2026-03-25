defmodule VetService.Integration.AttestationFlowTest do
  use ExUnit.Case, async: false

  alias VetService.Attestation.AttestationAPI
  alias VetService.Attestation.Consensus

  describe "attestation submission and consensus" do
    test "submit multiple attestations with the same findings_hash -> agreement_ratio 1.0" do
      hash = "abc123deadbeef"
      pkg = "attest_flow_same_#{System.unique_integer([:positive])}"

      for _i <- 1..5 do
        :ok = AttestationAPI.submit(pkg, "1.0.0", hash)
      end

      consensus = AttestationAPI.query(pkg, "1.0.0")

      assert consensus.consensus_hash == hash
      assert consensus.agreement_ratio == 1.0
      assert consensus.total_attestations == 5
    end

    test "submit attestations with mixed findings_hashes -> agreement_ratio < 1.0" do
      pkg = "attest_flow_mixed_#{System.unique_integer([:positive])}"

      :ok = AttestationAPI.submit(pkg, "1.0.0", "hash_a")
      :ok = AttestationAPI.submit(pkg, "1.0.0", "hash_a")
      :ok = AttestationAPI.submit(pkg, "1.0.0", "hash_b")
      :ok = AttestationAPI.submit(pkg, "1.0.0", "hash_c")

      consensus = AttestationAPI.query(pkg, "1.0.0")

      assert consensus.consensus_hash == "hash_a"
      assert consensus.agreement_ratio == 0.5
      assert consensus.total_attestations == 4
    end

    test "query returns attestation info for a package version" do
      pkg = "attest_flow_empty_#{System.unique_integer([:positive])}"
      result = AttestationAPI.query(pkg, "2.0.0")

      assert result.package_name == pkg
      assert result.version == "2.0.0"
      assert result.total_attestations == 0
      assert result.agreement_ratio == 0.0
    end

    test "consensus with empty list returns zero values" do
      result = Consensus.compute([])

      assert result.consensus_hash == nil
      assert result.agreement_ratio == 0.0
      assert result.total_attestations == 0
    end

    test "compute_consensus still works with in-memory attestation maps" do
      attestations = [
        %{findings_hash: "findings_hash_xyz"},
        %{findings_hash: "findings_hash_xyz"}
      ]

      result = AttestationAPI.compute_consensus(attestations)

      assert result.consensus_hash == "findings_hash_xyz"
      assert result.agreement_ratio == 1.0
      assert result.total_attestations == 2
    end
  end
end
