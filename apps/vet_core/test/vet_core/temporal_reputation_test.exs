defmodule VetCore.TemporalReputationTest do
  use ExUnit.Case

  alias VetCore.TemporalReputation

  defp make_record(version, finding_count, categories \\ [], risk_score \\ 0) do
    %{
      version: version,
      scan_date: DateTime.utc_now() |> DateTime.add(-:rand.uniform(1000), :second),
      finding_count: finding_count,
      categories: categories,
      risk_score: risk_score
    }
  end

  defp make_clean_history(count) do
    Enum.map(1..count, fn i ->
      %{
        version: "1.0.#{i}",
        scan_date: DateTime.utc_now() |> DateTime.add(-i * 86400, :second),
        finding_count: 0,
        categories: [],
        risk_score: 0
      }
    end)
  end

  describe "build/2" do
    test "with empty history returns trust_score 0.0" do
      rep = TemporalReputation.build(:some_pkg, [])

      assert rep.trust_score == 0.0
      assert rep.versions_scanned == 0
      assert rep.clean_streak == 0
      assert rep.package_name == :some_pkg
    end

    test "with 10 clean versions returns high trust" do
      history = make_clean_history(10)

      rep = TemporalReputation.build(:clean_pkg, history)

      assert rep.trust_score > 0.5
      assert rep.versions_scanned == 10
      assert rep.clean_streak == 10
    end

    test "with mixed history returns moderate trust" do
      now = DateTime.utc_now()

      # Timeline: 5 clean old, 1 dirty, 3 clean recent
      # Oldest first (most negative offset)
      clean_old =
        Enum.map(1..5, fn i ->
          %{version: "0.#{i}.0", scan_date: DateTime.add(now, -(100 - i) * 86400, :second), finding_count: 0, categories: [], risk_score: 0}
        end)

      dirty = [
        %{version: "0.6.0", scan_date: DateTime.add(now, -50 * 86400, :second), finding_count: 3, categories: [:system_exec], risk_score: 50}
      ]

      clean_recent =
        Enum.map(1..3, fn i ->
          %{version: "1.#{i}.0", scan_date: DateTime.add(now, -i * 86400, :second), finding_count: 0, categories: [], risk_score: 0}
        end)

      history = clean_old ++ dirty ++ clean_recent

      rep = TemporalReputation.build(:mixed_pkg, history)

      # 9 clean versions would give high trust; mixed should be lower
      all_clean_rep = TemporalReputation.build(:clean_ref, make_clean_history(9))

      assert rep.trust_score > 0.0
      assert rep.trust_score < all_clean_rep.trust_score
      # After sorting by date: 5 clean old, 1 dirty, 3 clean recent
      # clean_streak counts from the end (most recent) backwards while finding_count == 0
      assert rep.clean_streak == 3
    end
  end

  describe "anomaly_score/2" do
    test "for clean package with new findings returns high anomaly" do
      history = make_clean_history(10)
      rep = TemporalReputation.build(:clean_pkg, history)

      current_findings = [
        %{category: :system_exec},
        %{category: :network_access}
      ]

      score = TemporalReputation.anomaly_score(rep, current_findings)

      # clean_streak >= 10, so base = 30, plus 2 new categories * 15 = 60
      assert score >= 30
    end

    test "for package with no history returns low anomaly" do
      rep = TemporalReputation.build(:new_pkg, [])

      current_findings = [
        %{category: :system_exec}
      ]

      score = TemporalReputation.anomaly_score(rep, current_findings)

      # No clean streak (0), so base = 0, new categories bonus = 15
      assert score <= 15
    end

    test "with no current findings returns 0 anomaly" do
      history = make_clean_history(10)
      rep = TemporalReputation.build(:clean_pkg, history)

      score = TemporalReputation.anomaly_score(rep, [])

      assert score == 0
    end

    test "with new category appearing gets bonus applied" do
      # History has :file_access findings
      history = [
        %{version: "1.0.0", scan_date: DateTime.utc_now() |> DateTime.add(-86400, :second), finding_count: 1, categories: [:file_access], risk_score: 10}
      ]

      rep = TemporalReputation.build(:pkg, history)

      # Current findings include a NEW category not in history
      current_with_new = [%{category: :system_exec}]
      current_without_new = [%{category: :file_access}]

      score_new = TemporalReputation.anomaly_score(rep, current_with_new)
      score_old = TemporalReputation.anomaly_score(rep, current_without_new)

      # New category should get a bonus over existing category
      assert score_new > score_old
    end
  end
end
