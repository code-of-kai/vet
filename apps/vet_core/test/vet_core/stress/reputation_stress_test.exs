defmodule VetCore.Stress.ReputationStressTest do
  use ExUnit.Case, async: true

  alias VetCore.TemporalReputation
  alias VetCore.Types.Finding

  @moduletag timeout: 60_000

  describe "build with 10,000 version records" do
    test "handles large history without crashing or taking too long" do
      history =
        Enum.map(1..10_000, fn i ->
          %{
            version: "1.0.#{i}",
            scan_date: DateTime.add(~U[2020-01-01 00:00:00Z], i * 86400, :second),
            finding_count: 0,
            categories: [],
            risk_score: 0
          }
        end)

      {elapsed_us, reputation} =
        :timer.tc(fn ->
          TemporalReputation.build(:large_pkg, history)
        end)

      elapsed_ms = elapsed_us / 1_000

      assert %TemporalReputation{} = reputation
      assert reputation.versions_scanned == 10_000
      assert reputation.clean_streak == 10_000
      assert reputation.package_name == :large_pkg

      assert elapsed_ms < 5_000,
             "Building reputation for 10,000 versions took #{elapsed_ms}ms, expected < 5000ms"
    end

    test "10,000 versions with last 100 having findings" do
      clean_history =
        Enum.map(1..9_900, fn i ->
          %{
            version: "1.0.#{i}",
            scan_date: DateTime.add(~U[2020-01-01 00:00:00Z], i * 86400, :second),
            finding_count: 0,
            categories: [],
            risk_score: 0
          }
        end)

      dirty_history =
        Enum.map(9_901..10_000, fn i ->
          %{
            version: "1.0.#{i}",
            scan_date: DateTime.add(~U[2020-01-01 00:00:00Z], i * 86400, :second),
            finding_count: 3,
            categories: [:system_exec],
            risk_score: 45
          }
        end)

      history = clean_history ++ dirty_history

      reputation = TemporalReputation.build(:mixed_pkg, history)

      assert reputation.versions_scanned == 10_000
      # The last 100 have findings, so clean_streak is 0
      assert reputation.clean_streak == 0
    end
  end

  describe "anomaly_score with 1000 findings" do
    test "handles large finding list without crashing" do
      history =
        Enum.map(1..20, fn i ->
          %{
            version: "1.0.#{i}",
            scan_date: DateTime.add(~U[2020-01-01 00:00:00Z], i * 86400, :second),
            finding_count: 0,
            categories: [],
            risk_score: 0
          }
        end)

      reputation = TemporalReputation.build(:clean_pkg, history)

      # 1000 findings across many categories
      categories = [:system_exec, :code_eval, :network_access, :file_access, :env_access, :obfuscation, :shady_links, :compiler_hooks]

      findings =
        Enum.map(1..1000, fn i ->
          %Finding{
            dep_name: :clean_pkg,
            file_path: "lib/evil.ex",
            line: i,
            check_id: :test,
            category: Enum.at(categories, rem(i, length(categories))),
            severity: :critical,
            description: "Finding ##{i}"
          }
        end)

      score = TemporalReputation.anomaly_score(reputation, findings)

      assert is_integer(score)
      assert score >= 0
      assert score <= 100, "Anomaly score should cap at 100, got #{score}"
    end
  end

  describe "empty history" do
    test "trust_score is 0.0" do
      reputation = TemporalReputation.build(:new_pkg, [])

      assert reputation.trust_score == 0.0
      assert reputation.versions_scanned == 0
      assert reputation.clean_streak == 0
    end

    test "anomaly_score with empty history and no findings returns 0" do
      reputation = TemporalReputation.build(:new_pkg, [])
      score = TemporalReputation.anomaly_score(reputation, [])

      assert score == 0
    end
  end

  describe "all clean history" do
    test "trust_score approaches 1.0 with many clean versions" do
      # With 20+ clean versions, age_bonus maxes at 1.0, and clean_ratio is 1.0
      # trust = 1.0 * 0.6 + 1.0 * 0.4 = 1.0
      history =
        Enum.map(1..50, fn i ->
          %{
            version: "1.0.#{i}",
            scan_date: DateTime.add(~U[2020-01-01 00:00:00Z], i * 86400, :second),
            finding_count: 0,
            categories: [],
            risk_score: 0
          }
        end)

      reputation = TemporalReputation.build(:trusted_pkg, history)

      # Baseline: trust_score formula is clean_ratio * 0.6 + age_bonus * 0.4
      # With all clean: clean_ratio = 50/50 = 1.0, age_bonus = min(1.0, 50/20) = 1.0
      # trust = 1.0 * 0.6 + 1.0 * 0.4 = 1.0
      assert reputation.trust_score == 1.0
    end

    test "trust_score with exactly 1 clean version" do
      # clean_ratio = 1/1 = 1.0, age_bonus = min(1.0, 1/20) = 0.05
      # trust = 1.0 * 0.6 + 0.05 * 0.4 = 0.62
      history = [
        %{
          version: "1.0.0",
          scan_date: ~U[2020-01-01 00:00:00Z],
          finding_count: 0,
          categories: [],
          risk_score: 0
        }
      ]

      reputation = TemporalReputation.build(:single_pkg, history)

      assert reputation.trust_score == 0.62
      assert reputation.clean_streak == 1
    end
  end
end
