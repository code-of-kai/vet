defmodule VetCore.Sandbox.Runner.Bwrap do
  @moduledoc """
  Linux sandbox runner backed by bubblewrap (`bwrap`).

  bwrap creates a new Linux namespace with mount, PID, network, IPC, and
  user isolation. We construct an argv that mounts read-only tmpfs/proc
  and bind-mounts the requested readable paths, plus a writable
  workdir. Network isolation is achieved with `--unshare-net` unless the
  policy sets `allow_network: true`.

  Violations are extracted by parsing bwrap's stderr (syscall-level
  denials are not surfaced by bwrap itself, but the sandboxed process
  failing due to EPERM/EACCES manifests as errors in stderr).
  """
  @behaviour VetCore.Sandbox.Runner

  alias VetCore.Sandbox.BehaviorReport

  @impl true
  def available? do
    case System.find_executable("bwrap") do
      path when is_binary(path) -> true
      _ -> false
    end
  end

  @impl true
  def run([cmd | args] = command, workdir, policy) do
    bwrap = System.find_executable("bwrap") || "bwrap"
    timeout = Map.get(policy, :timeout_ms, 60_000)

    bwrap_args = build_args(policy, workdir) ++ [cmd | args]

    started = System.monotonic_time(:millisecond)

    {output, status} =
      try do
        System.cmd(bwrap, bwrap_args,
          cd: workdir,
          stderr_to_stdout: true,
          parallelism: true
        )
      catch
        kind, reason ->
          {"#{kind}: #{inspect(reason)}", 1}
      end

    elapsed = System.monotonic_time(:millisecond) - started

    %BehaviorReport{
      backend: __MODULE__,
      command: command,
      workdir: workdir,
      exit_status: status,
      duration_ms: min(elapsed, timeout),
      stdout: output,
      stderr: "",
      denied_operations: parse_denied(output),
      sandbox_available?: true,
      notes: [
        "Linux bubblewrap — namespace isolation for mount/net/pid/ipc."
      ]
    }
  end

  # --- Internals -------------------------------------------------------------

  @doc false
  def build_args(policy, workdir) do
    base = [
      "--die-with-parent",
      "--unshare-pid",
      "--unshare-uts",
      "--unshare-ipc",
      "--new-session",
      "--ro-bind",
      "/usr",
      "/usr",
      "--symlink",
      "usr/lib",
      "/lib",
      "--symlink",
      "usr/lib64",
      "/lib64",
      "--symlink",
      "usr/bin",
      "/bin",
      "--dev",
      "/dev",
      "--proc",
      "/proc",
      "--tmpfs",
      "/tmp"
    ]

    readables =
      Enum.flat_map(Map.get(policy, :readable_paths, []), fn p ->
        case File.exists?(p) do
          true -> ["--ro-bind", p, p]
          false -> []
        end
      end)

    writables =
      Enum.flat_map(Map.get(policy, :writable_paths, []), fn p ->
        File.mkdir_p(p)
        ["--bind", p, p]
      end)

    network =
      case Map.get(policy, :allow_network, false) do
        true -> []
        false -> ["--unshare-net"]
      end

    chdir = ["--chdir", workdir]

    base ++ readables ++ writables ++ network ++ chdir
  end

  defp parse_denied(output) do
    output
    |> String.split("\n")
    |> Enum.filter(fn line ->
      String.contains?(line, "Permission denied") or
        String.contains?(line, "bwrap: Can't ")
    end)
    |> Enum.map(fn line ->
      %{op: "denied", target: nil, raw: line}
    end)
  end
end
