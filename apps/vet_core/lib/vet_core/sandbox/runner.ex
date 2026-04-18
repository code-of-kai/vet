defmodule VetCore.Sandbox.Runner do
  @moduledoc """
  Behaviour for sandbox runners and dispatcher to the right backend.

  Each backend (`SandboxExec`, `Bwrap`, `Stub`) takes a command + working
  directory + policy and returns a `VetCore.Sandbox.BehaviorReport`.

  The dispatcher picks a backend based on platform and tool availability:

  | Platform | Tool present?           | Backend       |
  | -------- | ----------------------- | ------------- |
  | macOS    | `/usr/bin/sandbox-exec` | `SandboxExec` |
  | Linux    | `bwrap` on PATH         | `Bwrap`       |
  | other    | none                    | `Stub`        |

  The Stub backend runs the command without isolation but still returns
  a `BehaviorReport` (with `sandbox_available?: false`). Callers MUST
  check `sandbox_available?` before treating a clean Stub report as
  evidence of safe behavior.
  """

  alias VetCore.Sandbox.BehaviorReport

  @type policy :: %{
          required(:allow_network) => boolean(),
          required(:allow_subprocess) => boolean(),
          required(:writable_paths) => [String.t()],
          required(:readable_paths) => [String.t()],
          optional(:timeout_ms) => pos_integer()
        }

  @callback run(
              command :: [String.t()],
              workdir :: String.t(),
              policy :: policy()
            ) :: BehaviorReport.t()

  @callback available?() :: boolean()

  @doc """
  Pick the best available sandbox backend for this host.
  """
  @spec backend() :: module()
  def backend do
    cond do
      :os.type() == {:unix, :darwin} and VetCore.Sandbox.Runner.SandboxExec.available?() ->
        VetCore.Sandbox.Runner.SandboxExec

      :os.type() == {:unix, :linux} and VetCore.Sandbox.Runner.Bwrap.available?() ->
        VetCore.Sandbox.Runner.Bwrap

      true ->
        VetCore.Sandbox.Runner.Stub
    end
  end

  @doc """
  Run `command` in `workdir` under `policy` using the auto-detected
  backend. Equivalent to `backend().run(command, workdir, policy)`.
  """
  @spec run([String.t()], String.t(), policy()) :: BehaviorReport.t()
  def run(command, workdir, policy) do
    backend().run(command, workdir, policy)
  end

  @doc """
  A reasonable default policy for compiling an unknown package: no
  network, no subprocesses, write-only access to the working directory,
  read access to project_path and the OTP/Elixir lib paths required for
  compilation.
  """
  @spec compile_policy(String.t()) :: policy()
  def compile_policy(workdir) do
    %{
      allow_network: false,
      allow_subprocess: false,
      writable_paths: [workdir],
      readable_paths: [
        workdir,
        :code.root_dir() |> to_string(),
        Path.expand("~/.mix/elixir"),
        Path.expand("~/.asdf"),
        "/usr/lib",
        "/usr/local/lib"
      ],
      timeout_ms: 60_000
    }
  end
end
