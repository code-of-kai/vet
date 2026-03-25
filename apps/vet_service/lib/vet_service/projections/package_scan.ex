defmodule VetService.Projections.PackageScan do
  @moduledoc "Read-model projection for the latest scan of a package version."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "package_scans" do
    field :package_name, :string
    field :version, :string
    field :risk_score, :integer, default: 0
    field :risk_level, :string, default: "low"
    field :findings_count, :integer, default: 0
    field :last_scanned_at, :utc_datetime
    field :status, :string, default: "pending"

    timestamps(type: :utc_datetime)
  end

  @required_fields ~w(package_name version)a
  @optional_fields ~w(risk_score risk_level findings_count last_scanned_at status)a

  def changeset(scan, attrs) do
    scan
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, ~w(pending scanning completed failed))
    |> validate_inclusion(:risk_level, ~w(low medium high critical))
  end
end
