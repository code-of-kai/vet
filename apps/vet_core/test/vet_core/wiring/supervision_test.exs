defmodule VetCore.Wiring.SupervisionTest do
  use ExUnit.Case, async: true

  describe "OTP supervision tree" do
    test "VetCore.Application starts correctly" do
      # The application is already started by the test runner.
      # Verify it's in the list of started applications.
      started = Application.started_applications()
      assert Enum.any?(started, fn {app, _desc, _vsn} -> app == :vet_core end)
    end

    test "VetCore.ScanSupervisor is running" do
      pid = Process.whereis(VetCore.ScanSupervisor)
      assert is_pid(pid)
      assert Process.alive?(pid)
    end

    test "VetCore.Metadata.RateLimiter is running" do
      pid = Process.whereis(VetCore.Metadata.RateLimiter)
      assert is_pid(pid)
      assert Process.alive?(pid)
    end

    test "Task.Supervisor can accept tasks" do
      task = Task.Supervisor.async(VetCore.ScanSupervisor, fn -> :ok end)
      assert Task.await(task) == :ok
    end
  end
end
