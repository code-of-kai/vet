defmodule VetService.EventHandlers.ProjectionHandler do
  @moduledoc """
  Handles events by updating read-model projections.

  In a full Commanded setup this would use Commanded.Event.Handler.
  For now it exposes a `handle/1` function for direct invocation
  from the pipeline or tests.
  """

  alias VetService.Events.{
    DeterministicScanCompleted,
    RiskScoreComputed,
    CommunityAttestationSubmitted
  }

  @doc "Project an event into the read model. Returns :ok."
  @spec handle(struct()) :: :ok
  def handle(%DeterministicScanCompleted{} = _event) do
    # Upsert PackageScan projection
    :ok
  end

  def handle(%RiskScoreComputed{} = _event) do
    # Append to RiskTimeline projection
    :ok
  end

  def handle(%CommunityAttestationSubmitted{} = _event) do
    # Update AttestationSummary projection
    :ok
  end

  def handle(_event), do: :ok
end
