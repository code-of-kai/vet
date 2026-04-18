defmodule VetCore.Sandbox.Runner.SandboxExec do
  @moduledoc """
  macOS sandbox runner backed by Apple's `sandbox-exec` (Seatbelt).

  Generates a Seatbelt SBPL profile from the policy, writes it to a
  temp file, and invokes the command via
  `sandbox-exec -f <profile> <command>`.

  Seatbelt is technically deprecated in favor of the App Sandbox
  framework, but `sandbox-exec` continues to ship with macOS and is the
  only general-purpose CLI sandbox that comes with the OS. We treat
  deprecation as "Apple won't add new features," not "tomorrow it stops
  working."

  Violations are extracted by parsing `sandbox-exec` deny output on
  stderr (lines beginning with `Sandbox: ... deny `).
  """
  @behaviour VetCore.Sandbox.Runner

  alias VetCore.Sandbox.BehaviorReport

  @sandbox_exec "/usr/bin/sandbox-exec"

  @impl true
  def available? do
    File.regular?(@sandbox_exec)
  end

  @impl true
  def run([cmd | args] = command, workdir, policy) do
    profile = build_profile(policy, workdir)
    profile_file = write_profile(profile)
    timeout = Map.get(policy, :timeout_ms, 60_000)

    started = System.monotonic_time(:millisecond)

    {output, status} =
      try do
        System.cmd(@sandbox_exec, ["-f", profile_file, cmd | args],
          cd: workdir,
          stderr_to_stdout: true,
          parallelism: true
        )
      catch
        kind, reason ->
          {"#{kind}: #{inspect(reason)}", 1}
      end

    elapsed = System.monotonic_time(:millisecond) - started

    File.rm(profile_file)

    denied = parse_denied(output)

    %BehaviorReport{
      backend: __MODULE__,
      command: command,
      workdir: workdir,
      exit_status: status,
      duration_ms: min(elapsed, timeout),
      stdout: output,
      stderr: "",
      denied_operations: denied,
      sandbox_available?: true,
      notes: [
        "macOS sandbox-exec (Seatbelt) — denies are visible in the audit " <>
          "log if any policy rule rejects an operation."
      ]
    }
  end

  # --- Internals -------------------------------------------------------------

  @doc false
  def build_profile(policy, workdir) do
    base = """
    (version 1)
    (deny default)
    ; Allow process to operate within its own state.
    (allow process-fork)
    (allow process-info* (target self))
    (allow signal (target self))
    ; Always allow read on workdir (compilation needs to read sources).
    (allow file-read* (subpath "#{escape(workdir)}"))
    ; Always allow read of system code paths.
    (allow file-read* (subpath "/usr/lib") (subpath "/System/Library"))
    """

    base
    |> add_writable_paths(policy)
    |> add_readable_paths(policy)
    |> add_subprocess_rules(policy)
    |> add_network_rules(policy)
  end

  defp add_writable_paths(profile, %{writable_paths: paths}) do
    rules = for p <- paths, do: "(allow file-write* (subpath \"#{escape(p)}\"))"
    profile <> Enum.join(rules, "\n") <> "\n"
  end

  defp add_writable_paths(profile, _), do: profile

  defp add_readable_paths(profile, %{readable_paths: paths}) do
    rules = for p <- paths, do: "(allow file-read* (subpath \"#{escape(p)}\"))"
    profile <> Enum.join(rules, "\n") <> "\n"
  end

  defp add_readable_paths(profile, _), do: profile

  defp add_subprocess_rules(profile, %{allow_subprocess: true}) do
    profile <> "(allow process-exec)\n"
  end

  defp add_subprocess_rules(profile, _), do: profile

  defp add_network_rules(profile, %{allow_network: true}) do
    profile <> "(allow network*)\n"
  end

  defp add_network_rules(profile, _), do: profile

  defp escape(path), do: String.replace(to_string(path), "\"", "\\\"")

  defp write_profile(profile) do
    file =
      Path.join(
        System.tmp_dir!(),
        "vet_sbpl_#{System.unique_integer([:positive])}.sb"
      )

    File.write!(file, profile)
    file
  end

  # `sandbox-exec` writes deny lines to the unified system log, but the
  # command output itself contains `Sandbox: deny` lines on recent macOS
  # versions when the process is denied a syscall. Parse them best-effort.
  defp parse_denied(output) do
    output
    |> String.split("\n")
    |> Enum.filter(&String.contains?(&1, "Sandbox:"))
    |> Enum.filter(&String.contains?(&1, "deny"))
    |> Enum.map(&parse_denied_line/1)
  end

  defp parse_denied_line(line) do
    # Example: "Sandbox: cc(12345) deny(1) file-write-create /tmp/foo"
    [_, rest] = String.split(line, "deny", parts: 2)
    pieces = String.split(String.trim(rest), " ", trim: true)

    {op, target} =
      case pieces do
        [_count, op | rest] -> {op, Enum.join(rest, " ")}
        [op | rest] -> {op, Enum.join(rest, " ")}
        _ -> {"unknown", nil}
      end

    %{op: op, target: target, raw: line}
  end
end
