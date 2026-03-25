defmodule VetService.Integration.AttestationFlowTest do
  use ExUnit.Case, async: true

  alias VetService.Attestation.AttestationAPI
  alias VetService.Attestation.Consensus

  describe "attestation submission and consensus" do
    test "submit multiple attestations with the same findings_hash → agreement_ratio 1.0" do
      hash = "abc123deadbeef"

      attestations =
        for _i <- 1..5 do
          {:ok, event} = AttestationAPI.submit("my_package", "1.0.0", hash)
          event
        end

      consensus = AttestationAPI.compute_consensus(attestations)

      assert consensus.consensus_hash == hash
      assert consensus.agreement_ratio == 1.0
      assert consensus.total_attestations == 5
    end

    test "submit attestations with mixed findings_hashes → agreement_ratio < 1.0" do
      {:ok, e1} = AttestationAPI.submit("my_package", "1.0.0", "hash_a")
      {:ok, e2} = AttestationAPI.submit("my_package", "1.0.0", "hash_a")
      {:ok, e3} = AttestationAPI.submit("my_package", "1.0.0", "hash_b")
      {:ok, e4} = AttestationAPI.submit("my_package", "1.0.0", "hash_c")

      consensus = AttestationAPI.compute_consensus([e1, e2, e3, e4])

      assert consensus.consensus_hash == "hash_a"
      assert consensus.agreement_ratio == 0.5
      assert consensus.total_attestations == 4
    end

    test "query returns attestation info for a package version" do
      {:ok, result} = AttestationAPI.query("some_package", "2.0.0")

      assert result.package_name == "some_package"
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

    test "submitted attestation events have required fields" do
      {:ok, event} = AttestationAPI.submit("test_pkg", "3.0.0", "findings_hash_xyz")

      assert event.package_name == "test_pkg"
      assert event.version == "3.0.0"
      assert event.findings_hash == "findings_hash_xyz"
      assert event.submitter_id == "anonymous"
      assert is_binary(event.attestation_id)
      assert %DateTime{} = event.submitted_at
    end
  end
end
