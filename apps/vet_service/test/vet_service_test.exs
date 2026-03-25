defmodule VetServiceTest do
  use ExUnit.Case, async: false

  alias VetService.Events.{
    PackageVersionPublished,
    DeterministicScanCompleted,
    LLMReviewCompleted,
    CommunityAttestationSubmitted,
    FindingSuppressed,
    RiskScoreComputed,
    PatternProfileShiftDetected
  }

  alias VetService.Attestation.Consensus
  alias VetService.Aggregates.PackageVersion
  alias VetService.Commands.{ScanPackage, SubmitAttestation, SuppressFinding}

  # --- Module existence ---

  describe "VetService module" do
    test "module exists" do
      assert Code.ensure_loaded?(VetService)
    end

    test "application module exists" do
      assert Code.ensure_loaded?(VetService.Application)
    end

    test "repo module exists" do
      assert Code.ensure_loaded?(VetService.Repo)
    end
  end

  # --- Event struct creation ---

  describe "event structs" do
    test "PackageVersionPublished" do
      event = %PackageVersionPublished{
        package_name: "jason",
        version: "1.4.4",
        published_at: ~U[2025-01-01 00:00:00Z],
        hex_metadata: %{"licenses" => ["Apache-2.0"]}
      }

      assert event.package_name == "jason"
      assert event.version == "1.4.4"
      assert event.hex_metadata["licenses"] == ["Apache-2.0"]
    end

    test "DeterministicScanCompleted" do
      event = %DeterministicScanCompleted{
        package_name: "poison",
        version: "6.0.0",
        scan_id: "scan-001",
        findings: [%{rule: "network_call", severity: :medium}],
        risk_score: 42,
        scanned_at: ~U[2025-06-01 12:00:00Z]
      }

      assert event.risk_score == 42
      assert length(event.findings) == 1
    end

    test "LLMReviewCompleted" do
      event = %LLMReviewCompleted{
        package_name: "plug",
        version: "1.16.0",
        scan_id: "scan-002",
        ai_analysis: %{summary: "No issues found"},
        model: "claude-opus-4-20250514",
        reviewed_at: ~U[2025-06-01 13:00:00Z]
      }

      assert event.model == "claude-opus-4-20250514"
    end

    test "CommunityAttestationSubmitted" do
      event = %CommunityAttestationSubmitted{
        package_name: "ecto",
        version: "3.12.0",
        attestation_id: "att-001",
        findings_hash: "abc123",
        submitter_id: "user-42",
        submitted_at: ~U[2025-06-02 10:00:00Z]
      }

      assert event.findings_hash == "abc123"
    end

    test "FindingSuppressed" do
      event = %FindingSuppressed{
        package_name: "httpoison",
        version: "2.0.0",
        finding_id: "f-001",
        reason: "Known safe pattern",
        suppressed_by: "admin"
      }

      assert event.reason == "Known safe pattern"
    end

    test "RiskScoreComputed" do
      event = %RiskScoreComputed{
        package_name: "tesla",
        version: "1.9.0",
        score: 15,
        level: :low,
        factors: %{network_calls: 2, native_code: false}
      }

      assert event.level == :low
    end

    test "PatternProfileShiftDetected" do
      event = %PatternProfileShiftDetected{
        package_name: "mint",
        from_version: "1.5.0",
        to_version: "1.6.0",
        added_categories: [:file_system],
        removed_categories: [],
        severity: :medium
      }

      assert event.severity == :medium
      assert :file_system in event.added_categories
    end
  end

  # --- Consensus computation ---

  describe "Consensus.compute/1" do
    test "returns zero consensus for empty list" do
      result = Consensus.compute([])

      assert result.consensus_hash == nil
      assert result.agreement_ratio == 0.0
      assert result.total_attestations == 0
    end

    test "returns full consensus when all attestations agree" do
      attestations = [
        %{findings_hash: "abc123"},
        %{findings_hash: "abc123"},
        %{findings_hash: "abc123"}
      ]

      result = Consensus.compute(attestations)

      assert result.consensus_hash == "abc123"
      assert result.agreement_ratio == 1.0
      assert result.total_attestations == 3
    end

    test "returns majority consensus with mixed attestations" do
      attestations = [
        %{findings_hash: "abc123"},
        %{findings_hash: "abc123"},
        %{findings_hash: "def456"},
        %{findings_hash: "abc123"},
        %{findings_hash: "def456"}
      ]

      result = Consensus.compute(attestations)

      assert result.consensus_hash == "abc123"
      assert_in_delta result.agreement_ratio, 0.6, 0.01
      assert result.total_attestations == 5
    end

    test "handles single attestation" do
      result = Consensus.compute([%{findings_hash: "only-one"}])

      assert result.consensus_hash == "only-one"
      assert result.agreement_ratio == 1.0
      assert result.total_attestations == 1
    end

    test "works with event structs" do
      attestations = [
        %CommunityAttestationSubmitted{
          package_name: "ecto",
          version: "3.12.0",
          attestation_id: "a1",
          findings_hash: "hash-a",
          submitter_id: "u1",
          submitted_at: ~U[2025-01-01 00:00:00Z]
        },
        %CommunityAttestationSubmitted{
          package_name: "ecto",
          version: "3.12.0",
          attestation_id: "a2",
          findings_hash: "hash-a",
          submitter_id: "u2",
          submitted_at: ~U[2025-01-01 01:00:00Z]
        }
      ]

      result = Consensus.compute(attestations)

      assert result.consensus_hash == "hash-a"
      assert result.agreement_ratio == 1.0
    end
  end

  # --- Aggregate behavior ---

  describe "PackageVersion aggregate" do
    test "handles ScanPackage command on fresh aggregate" do
      aggregate = %PackageVersion{}
      command = %ScanPackage{package_name: "jason", version: "1.4.4", scan_id: "s1"}

      event = PackageVersion.execute(aggregate, command)

      assert %DeterministicScanCompleted{} = event
      assert event.package_name == "jason"
      assert event.scan_id == "s1"
    end

    test "applies DeterministicScanCompleted event" do
      aggregate = %PackageVersion{}

      event = %DeterministicScanCompleted{
        package_name: "jason",
        version: "1.4.4",
        scan_id: "s1",
        findings: [%{rule: "eval_usage"}],
        risk_score: 25,
        scanned_at: ~U[2025-06-01 12:00:00Z]
      }

      updated = PackageVersion.apply(aggregate, event)

      assert updated.package_name == "jason"
      assert updated.risk_score == 25
      assert updated.current_scan.scan_id == "s1"
    end

    test "handles SubmitAttestation and applies event" do
      aggregate = %PackageVersion{package_name: "jason", version: "1.4.4"}

      command = %SubmitAttestation{
        package_name: "jason",
        version: "1.4.4",
        attestation_id: "att-1",
        findings_hash: "hash-x",
        submitter_id: "user-1"
      }

      event = PackageVersion.execute(aggregate, command)
      assert %CommunityAttestationSubmitted{} = event

      updated = PackageVersion.apply(aggregate, event)
      assert length(updated.attestations) == 1
    end

    test "rejects duplicate suppression" do
      aggregate = %PackageVersion{
        package_name: "jason",
        version: "1.4.4",
        suppressions: [%{finding_id: "f-1", reason: "safe", suppressed_by: "admin"}]
      }

      command = %SuppressFinding{
        package_name: "jason",
        version: "1.4.4",
        finding_id: "f-1",
        reason: "also safe",
        suppressed_by: "other-admin"
      }

      assert {:error, :already_suppressed} = PackageVersion.execute(aggregate, command)
    end
  end

  # --- Public API (backed by ETS Store) ---

  describe "VetService public API" do
    test "record and retrieve scan" do
      VetService.record_scan("test_pkg", "1.0.0", %{risk_score: 42})
      assert {:ok, %{risk_score: 42}} = VetService.get_scan("test_pkg", "1.0.0")
    end

    test "submit attestation and get consensus" do
      VetService.submit_attestation("test_pkg2", "1.0.0", %{findings_hash: "abc"})
      VetService.submit_attestation("test_pkg2", "1.0.0", %{findings_hash: "abc"})
      consensus = VetService.get_consensus("test_pkg2", "1.0.0")
      assert is_map(consensus)
    end

    test "list_scans returns recorded scans" do
      VetService.record_scan("list_test", "1.0.0", %{risk_score: 10})
      scans = VetService.list_scans()
      assert Enum.any?(scans, fn s -> s.key == {"list_test", "1.0.0"} end)
    end
  end
end
