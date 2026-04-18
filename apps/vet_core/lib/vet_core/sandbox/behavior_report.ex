defmodule VetCore.Sandbox.BehaviorReport do
  @moduledoc """
  Result of running a command inside an OS sandbox.

  Captures everything observed during the run: exit status, captured
  output, runtime, and (when the sandbox supports it) a list of denied
  operations. Different sandbox backends populate different subsets of
  the optional fields:

  - `denied_operations` is populated by sandbox-exec audit-log parsing
    (macOS) and bwrap stderr parsing (Linux); empty otherwise.
  - `files_written` records absolute paths the sandbox observed writes
    to. Best-effort and backend-dependent.
  - `network_attempts` records `{host, port}` tuples seen attempting
    network connections.
  - `processes_spawned` records executable paths of subprocess spawns
    detected through the sandbox audit log.
  """

  defstruct [
    :backend,
    :command,
    :workdir,
    :exit_status,
    :duration_ms,
    stdout: "",
    stderr: "",
    denied_operations: [],
    files_written: [],
    network_attempts: [],
    processes_spawned: [],
    sandbox_available?: true,
    notes: []
  ]

  @type denied_op :: %{
          op: String.t(),
          target: String.t() | nil,
          raw: String.t()
        }

  @type t :: %__MODULE__{
          backend: atom(),
          command: [String.t()],
          workdir: String.t(),
          exit_status: integer() | nil,
          duration_ms: non_neg_integer(),
          stdout: String.t(),
          stderr: String.t(),
          denied_operations: [denied_op()],
          files_written: [String.t()],
          network_attempts: [{String.t(), non_neg_integer()}],
          processes_spawned: [String.t()],
          sandbox_available?: boolean(),
          notes: [String.t()]
        }

  @doc """
  Returns `true` when the report indicates the sandboxed code attempted
  out-of-policy behavior — denied syscalls, network attempts, or writes
  outside the working directory.
  """
  @spec violations?(t()) :: boolean()
  def violations?(%__MODULE__{} = r) do
    r.denied_operations != [] or
      r.network_attempts != [] or
      Enum.any?(r.files_written, &outside_workdir?(&1, r.workdir)) or
      r.processes_spawned != []
  end

  defp outside_workdir?(path, workdir) do
    not String.starts_with?(Path.expand(path), Path.expand(workdir))
  end
end
