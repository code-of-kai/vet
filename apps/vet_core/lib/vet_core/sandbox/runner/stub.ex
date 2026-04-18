defmodule VetCore.Sandbox.Runner.Stub do
  @moduledoc """
  Fallback runner for hosts without an OS-level sandbox available.

  Runs the command directly with no isolation. The returned
  `BehaviorReport` has `sandbox_available?: false` — callers must treat
  a clean report from this backend as "no sandbox was applied," not as
  evidence the code was safe.
  """
  @behaviour VetCore.Sandbox.Runner

  alias VetCore.Sandbox.BehaviorReport

  @impl true
  def available?, do: true

  @impl true
  def run([cmd | args], workdir, policy) do
    timeout = Map.get(policy, :timeout_ms, 60_000)
    started = System.monotonic_time(:millisecond)

    {output, status} =
      try do
        System.cmd(cmd, args,
          cd: workdir,
          stderr_to_stdout: false,
          parallelism: true
        )
      catch
        kind, reason ->
          {"#{kind}: #{inspect(reason)}", 1}
      end

    elapsed = System.monotonic_time(:millisecond) - started

    %BehaviorReport{
      backend: __MODULE__,
      command: [cmd | args],
      workdir: workdir,
      exit_status: status,
      duration_ms: min(elapsed, timeout),
      stdout: output,
      stderr: "",
      sandbox_available?: false,
      notes: [
        "No OS sandbox detected on this host. Command ran with the " <>
          "developer's full privileges. The behavior report is provided for " <>
          "auditability but does NOT prove safety."
      ]
    }
  end
end
