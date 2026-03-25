defmodule VetService.Stress.ConsensusStressTest do
  use ExUnit.Case, async: true

  alias VetService.Attestation.Consensus

  @moduletag timeout: 60_000

  describe "10,000 attestations" do
    test "computes consensus in under 1 second with all same hash" do
      attestations =
        Enum.map(1..10_000, fn i ->
          %{findings_hash: "same_hash", submitter_id: "user_#{i}"}
        end)

      {elapsed_us, result} =
        :timer.tc(fn ->
          Consensus.compute(attestations)
        end)

      elapsed_ms = elapsed_us / 1_000

      assert result.consensus_hash == "same_hash"
      assert result.agreement_ratio == 1.0
      assert result.total_attestations == 10_000

      assert elapsed_ms < 1_000,
             "Consensus computation took #{elapsed_ms}ms, expected < 1000ms"
    end

    test "computes consensus in under 1 second with all different hashes" do
      attestations =
        Enum.map(1..10_000, fn i ->
          %{findings_hash: "hash_#{i}"}
        end)

      {elapsed_us, result} =
        :timer.tc(fn ->
          Consensus.compute(attestations)
        end)

      elapsed_ms = elapsed_us / 1_000

      # Each hash appears exactly once, so agreement_ratio = 1/10_000
      assert result.agreement_ratio == 1 / 10_000
      assert result.total_attestations == 10_000
      assert result.consensus_hash != nil

      assert elapsed_ms < 1_000,
             "Consensus computation took #{elapsed_ms}ms, expected < 1000ms"
    end

    test "computes correct agreement_ratio with majority hash" do
      # 7000 agree, 3000 differ
      majority =
        Enum.map(1..7_000, fn _i ->
          %{findings_hash: "majority_hash"}
        end)

      minority =
        Enum.map(1..3_000, fn i ->
          %{findings_hash: "minority_#{i}"}
        end)

      attestations = majority ++ minority

      {elapsed_us, result} =
        :timer.tc(fn ->
          Consensus.compute(attestations)
        end)

      elapsed_ms = elapsed_us / 1_000

      assert result.consensus_hash == "majority_hash"
      assert_in_delta result.agreement_ratio, 0.7, 0.001
      assert result.total_attestations == 10_000

      assert elapsed_ms < 1_000,
             "Consensus computation took #{elapsed_ms}ms, expected < 1000ms"
    end
  end

  describe "edge cases" do
    test "single attestation" do
      result = Consensus.compute([%{findings_hash: "only"}])

      assert result.consensus_hash == "only"
      assert result.agreement_ratio == 1.0
      assert result.total_attestations == 1
    end

    test "empty list" do
      result = Consensus.compute([])

      assert result.consensus_hash == nil
      assert result.agreement_ratio == 0.0
      assert result.total_attestations == 0
    end

    test "two attestations with different hashes" do
      result =
        Consensus.compute([
          %{findings_hash: "hash_a"},
          %{findings_hash: "hash_b"}
        ])

      assert result.agreement_ratio == 0.5
      assert result.total_attestations == 2
      assert result.consensus_hash in ["hash_a", "hash_b"]
    end

    test "attestations with nil hash" do
      result =
        Consensus.compute([
          %{findings_hash: nil},
          %{findings_hash: nil},
          %{findings_hash: "real"}
        ])

      # nil appears 2 times, "real" appears 1 time
      assert result.consensus_hash == nil
      assert_in_delta result.agreement_ratio, 2 / 3, 0.01
    end
  end
end
