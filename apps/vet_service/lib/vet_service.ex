defmodule VetService do
  @moduledoc """
  VetService — event-sourced backend for dependency security scanning.

  Orchestrates the full scan lifecycle:
  1. Hex publish events arrive via Broadway pipeline
  2. Deterministic scans run through Commanded command/event flow
  3. LLM reviews triggered asynchronously on interesting findings
  4. Community attestations aggregated for consensus
  5. Risk scores computed and projected for querying
  """
end
