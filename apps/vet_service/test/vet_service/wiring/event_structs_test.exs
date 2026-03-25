defmodule VetService.Wiring.EventStructsTest do
  use ExUnit.Case, async: true

  @events [
    VetService.Events.PackageVersionPublished,
    VetService.Events.DeterministicScanCompleted,
    VetService.Events.LLMReviewCompleted,
    VetService.Events.CommunityAttestationSubmitted,
    VetService.Events.FindingSuppressed,
    VetService.Events.RiskScoreComputed,
    VetService.Events.PatternProfileShiftDetected
  ]

  for event <- @events do
    describe "#{inspect(event)}" do
      test "module loads" do
        assert Code.ensure_loaded?(unquote(event))
      end

      test "has __struct__/0 (is a struct)" do
        Code.ensure_loaded!(unquote(event))
        assert function_exported?(unquote(event), :__struct__, 0)
      end

      test "can be created with struct/1 without crash" do
        s = struct(unquote(event))
        assert is_struct(s, unquote(event))
      end

      test "implements Jason.Encoder (can be encoded to JSON)" do
        s = struct(unquote(event))
        assert {:ok, json} = Jason.encode(s)
        assert is_binary(json)
      end
    end
  end
end
