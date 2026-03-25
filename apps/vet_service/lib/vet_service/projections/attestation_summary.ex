defmodule VetService.Projections.AttestationSummary do
  @moduledoc "Materialized view of attestation consensus for a package version."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "attestation_summaries" do
    field :package_name, :string
    field :version, :string
    field :consensus_hash, :string
    field :agreement_ratio, :float, default: 0.0
    field :total_attestations, :integer, default: 0

    timestamps(type: :utc_datetime)
  end

  def changeset(summary, attrs) do
    summary
    |> cast(attrs, [:package_name, :version, :consensus_hash, :agreement_ratio, :total_attestations])
    |> validate_required([:package_name, :version])
    |> validate_number(:agreement_ratio, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
  end
end
