defmodule VetService.StoreTest do
  use ExUnit.Case, async: false  # ETS named tables aren't async-safe

  setup do
    # Store is started by the application
    :ok
  end

  test "put and get scan" do
    VetService.Store.put_scan("phoenix", "1.7.0", %{risk_score: 5})
    assert {:ok, %{risk_score: 5}} = VetService.Store.get_scan("phoenix", "1.7.0")
  end

  test "get non-existent scan" do
    assert {:error, :not_found} = VetService.Store.get_scan("nonexistent", "0.0.0")
  end

  test "put and get attestations" do
    VetService.Store.put_attestation("plug", "1.0.0", %{hash: "abc", scanner: "user1"})
    VetService.Store.put_attestation("plug", "1.0.0", %{hash: "abc", scanner: "user2"})
    attestations = VetService.Store.get_attestations("plug", "1.0.0")
    assert length(attestations) == 2
  end

  test "risk timeline" do
    VetService.Store.put_risk_score("ecto", "3.0.0", 10)
    Process.sleep(1)  # ensure different timestamps
    VetService.Store.put_risk_score("ecto", "3.1.0", 5)
    timeline = VetService.Store.get_risk_timeline("ecto")
    assert length(timeline) == 2
  end
end
