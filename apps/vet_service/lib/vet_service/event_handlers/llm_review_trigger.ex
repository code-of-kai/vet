defmodule VetService.EventHandlers.LLMReviewTrigger do
  @moduledoc """
  Listens for DeterministicScanCompleted events and triggers an LLM
  review when findings exceed a configurable threshold.
  """

  alias VetService.Events.DeterministicScanCompleted

  @risk_threshold 30

  @spec handle(struct()) :: :ok | {:trigger_review, String.t(), String.t(), String.t()}
  def handle(%DeterministicScanCompleted{risk_score: score} = event)
      when score >= @risk_threshold do
    # In production: dispatch an async LLM review job
    {:trigger_review, event.package_name, event.version, event.scan_id}
  end

  def handle(%DeterministicScanCompleted{}), do: :ok

  def handle(_event), do: :ok
end
