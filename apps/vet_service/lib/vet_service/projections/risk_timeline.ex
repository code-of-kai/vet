defmodule VetService.Projections.RiskTimeline do
  @moduledoc "Append-only projection tracking risk score over time for charting."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "risk_timeline" do
    field :package_name, :string
    field :version, :string
    field :risk_score, :integer
    field :scanned_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [:package_name, :version, :risk_score, :scanned_at])
    |> validate_required([:package_name, :version, :risk_score, :scanned_at])
  end
end
