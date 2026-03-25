defmodule VetService.Store do
  @moduledoc false
  use GenServer

  # Tables: :vet_scans, :vet_attestations, :vet_risk_timeline

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    :ets.new(:vet_scans, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(:vet_attestations, [:bag, :public, :named_table, read_concurrency: true])
    :ets.new(:vet_risk_timeline, [:ordered_set, :public, :named_table, read_concurrency: true])
    {:ok, %{}}
  end

  # Scan storage
  def put_scan(package_name, version, scan_result) do
    key = {package_name, version}
    :ets.insert(:vet_scans, {key, scan_result, DateTime.utc_now()})
    :ok
  end

  def get_scan(package_name, version) do
    case :ets.lookup(:vet_scans, {package_name, version}) do
      [{_key, result, _timestamp}] -> {:ok, result}
      [] -> {:error, :not_found}
    end
  end

  def list_scans do
    :ets.tab2list(:vet_scans)
    |> Enum.map(fn {key, result, timestamp} -> %{key: key, result: result, scanned_at: timestamp} end)
    |> Enum.sort_by(& &1.scanned_at, {:desc, DateTime})
  end

  # Attestation storage
  def put_attestation(package_name, version, attestation) do
    key = {package_name, version}
    :ets.insert(:vet_attestations, {key, attestation})
    :ok
  end

  def get_attestations(package_name, version) do
    :ets.lookup(:vet_attestations, {package_name, version})
    |> Enum.map(fn {_key, attestation} -> attestation end)
  end

  # Risk timeline
  def put_risk_score(package_name, version, score) do
    key = {package_name, version, DateTime.utc_now()}
    :ets.insert(:vet_risk_timeline, {key, score})
    :ok
  end

  def get_risk_timeline(package_name) do
    # Match on package_name in the key
    :ets.select(:vet_risk_timeline, [
      {{{:"$1", :"$2", :"$3"}, :"$4"},
       [{:==, :"$1", package_name}],
       [%{version: :"$2", timestamp: :"$3", score: :"$4"}]}
    ])
  end
end
