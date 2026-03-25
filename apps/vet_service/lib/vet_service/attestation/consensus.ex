defmodule VetService.Attestation.Consensus do
  @moduledoc """
  Computes consensus from a list of community attestations.

  Agreement is measured by the proportion of attestations that share
  the most common findings_hash.
  """

  @doc """
  Compute consensus from a list of attestation structs or maps
  that have a `:findings_hash` field.

  Returns a map with:
  - `consensus_hash` — the most common findings hash (nil if empty)
  - `agreement_ratio` — fraction of attestations matching the consensus hash
  - `total_attestations` — total count
  """
  @spec compute([map()]) :: %{
          consensus_hash: String.t() | nil,
          agreement_ratio: float(),
          total_attestations: non_neg_integer()
        }
  def compute([]) do
    %{consensus_hash: nil, agreement_ratio: 0.0, total_attestations: 0}
  end

  def compute(attestations) when is_list(attestations) do
    total = length(attestations)

    freq =
      attestations
      |> Enum.map(&extract_hash/1)
      |> Enum.frequencies()

    {consensus_hash, max_count} =
      Enum.max_by(freq, fn {_hash, count} -> count end)

    %{
      consensus_hash: consensus_hash,
      agreement_ratio: max_count / total,
      total_attestations: total
    }
  end

  defp extract_hash(%{findings_hash: hash}), do: hash
  defp extract_hash(map) when is_map(map), do: Map.get(map, :findings_hash)
end
