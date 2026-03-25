defmodule VetWeb.AttestationJSON do
  def show(%{attestation: attestation}) do
    %{data: attestation_data(attestation)}
  end

  defp attestation_data(attestation) do
    %{
      package: attestation.package,
      version: attestation.version
    }
    |> maybe_put(:id, Map.get(attestation, :id))
    |> maybe_put(:attester, Map.get(attestation, :attester))
    |> maybe_put(:decision, Map.get(attestation, :decision))
    |> maybe_put(:reason, Map.get(attestation, :reason))
    |> maybe_put(:created_at, Map.get(attestation, :created_at))
    |> maybe_put(:total_attestations, Map.get(attestation, :total_attestations))
    |> maybe_put(:approved, Map.get(attestation, :approved))
    |> maybe_put(:rejected, Map.get(attestation, :rejected))
    |> maybe_put(:attestations, Map.get(attestation, :attestations))
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
