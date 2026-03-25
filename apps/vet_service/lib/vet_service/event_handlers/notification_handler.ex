defmodule VetService.EventHandlers.NotificationHandler do
  @moduledoc """
  Sends notifications when notable events occur (e.g., high risk score,
  pattern profile shifts).
  """

  alias VetService.Events.{RiskScoreComputed, PatternProfileShiftDetected}

  @spec handle(struct()) :: :ok
  def handle(%RiskScoreComputed{level: :critical} = _event) do
    # Send alert for critical risk
    :ok
  end

  def handle(%PatternProfileShiftDetected{severity: severity} = _event)
      when severity in [:high, :critical] do
    # Send alert for significant pattern shifts
    :ok
  end

  def handle(_event), do: :ok
end
