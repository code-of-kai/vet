defmodule VetCore.TemporalReputation do
  @moduledoc false

  defstruct [
    :package_name,
    :versions_scanned,
    :clean_streak,
    :trust_score,
    history: []
  ]

  @type version_record :: %{
          version: String.t(),
          scan_date: DateTime.t(),
          finding_count: non_neg_integer(),
          categories: [atom()],
          risk_score: non_neg_integer()
        }

  @type t :: %__MODULE__{
          package_name: atom(),
          versions_scanned: non_neg_integer(),
          clean_streak: non_neg_integer(),
          trust_score: float(),
          history: [version_record()]
        }

  def build(package_name, scan_history) when is_list(scan_history) do
    sorted = Enum.sort_by(scan_history, & &1.scan_date, DateTime)

    clean_streak =
      sorted
      |> Enum.reverse()
      |> Enum.take_while(&(&1.finding_count == 0))
      |> length()

    trust_score = compute_trust(sorted, clean_streak)

    %__MODULE__{
      package_name: package_name,
      versions_scanned: length(sorted),
      clean_streak: clean_streak,
      trust_score: trust_score,
      history: sorted
    }
  end

  def anomaly_score(%__MODULE__{} = reputation, current_findings) do
    current_categories =
      current_findings
      |> Enum.map(& &1.category)
      |> Enum.uniq()

    historical_categories =
      reputation.history
      |> Enum.flat_map(& &1.categories)
      |> Enum.uniq()

    new_categories = current_categories -- historical_categories

    base =
      cond do
        reputation.clean_streak >= 10 and current_findings != [] -> 30
        reputation.clean_streak >= 5 and current_findings != [] -> 20
        reputation.clean_streak >= 1 and current_findings != [] -> 10
        true -> 0
      end

    category_bonus = length(new_categories) * 15

    min(100, base + category_bonus)
  end

  defp compute_trust(history, clean_streak) do
    total = length(history)

    if total == 0 do
      0.0
    else
      clean_ratio = clean_streak / max(total, 1)
      age_bonus = min(1.0, total / 20.0)
      Float.round(clean_ratio * 0.6 + age_bonus * 0.4, 2)
    end
  end
end
