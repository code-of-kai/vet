defmodule VetService.Events.LLMReviewCompleted do
  @moduledoc "Emitted when an LLM-based code review finishes."

  @derive Jason.Encoder
  defstruct [:package_name, :version, :scan_id, :ai_analysis, :model, :reviewed_at]
end
