defmodule VetCore.Checks.BeamImports do
  @moduledoc """
  Layer 1 — BEAM bytecode analysis.

  Scans a dependency's compiled `.beam` files and fires findings based on the
  `imports` chunk (the exact list of external MFAs the module references) and
  the `exports` chunk (which exposes meta-functions like
  `$handle_undefined_function/2`).

  Why this layer matters: source-level evasion mechanisms all collapse here.
  `defdelegate`, `.erl` files compiled to BEAM, atom-aliased module references
  (`String.to_atom("ss" <> "h")`), and macro-synthesized calls produce the same
  imports-chunk entries as a direct call would. You cannot hide a static call
  from the BEAM import table.

  The check runs only when `_build/<env>/lib/<dep>/ebin/` exists. If the
  dep has not been compiled, the check returns no findings rather than
  erroring.
  """
  use VetCore.Check

  alias VetCore.BEAM.BeamProfile
  alias VetCore.Types.Finding

  @category :bytecode_imports

  # Entire modules that are dangerous regardless of which function is called.
  # Every import of one of these fires a finding.
  @wildcard_modules %{
    ssh: "SSH client/server — remote shell, file transfer, tunneling",
    ssh_sftp: "SFTP file transfer client",
    ssh_connection: "Low-level SSH connection control",
    ssh_client_key_api: "SSH key handling",
    ssh_server_key_api: "SSH server key handling",
    ssh_sftpd: "SFTP daemon",
    ftp: "FTP client — data upload/download",
    httpd: "Embedded HTTP server — potential hidden listener",
    tftp: "TFTP client/server",
    inet_res: "Direct DNS resolver — DNS-based exfiltration vector",
    prim_file: "Non-public low-level file API (legitimate uses are vanishingly rare)",
    erl_eval: "Runtime Erlang expression evaluation"
  }

  # Specific dangerous MFAs that don't justify wildcarding the whole module.
  #
  # `:erlang.apply` and `:erlang.make_fun` are deliberately excluded:
  # they appear in nearly every compiled Elixir BEAM (every GenServer
  # callback, every Plug pipeline, every Phoenix controller dispatches
  # via apply). Layer 3's reflection-density check still aggregates
  # apply usage; flagging it again per-import here just buries the
  # signal under hundreds of warnings on legitimate framework code.
  @specific_imports %{
    {:inets, :start} => "Starts INETS subsystem (HTTP/FTP/TFTP services)",
    {:inets, :stop} => "Controls INETS subsystem",
    {:epp, :scan_file} => "Reads a file via the Erlang preprocessor",
    {:epp, :parse_file} => "Parses an Erlang source file",
    {:epp, :open} => "Opens a file for preprocessor scanning",
    {:os, :cmd} => "Shell command execution",
    {:erlang, :open_port} => "Opens an OS port (subprocess or socket)",
    {:erlang, :spawn_executable} => "Runs an OS executable",
    {:disk_log, :open} => "Opens an on-disk log (potential exfil sink)",
    {:disk_log, :log} => "Writes to an on-disk log",
    {:disk_log, :blog} => "Writes binary to an on-disk log"
  }

  # MFAs that are dangerous but widely used; warning rather than critical.
  @warning_imports MapSet.new([
                     {:inets, :start},
                     {:inets, :stop}
                   ])

  @impl true
  def run(%{name: dep_name} = _dep, project_path, _state) do
    case ebin_dirs(dep_name, project_path) do
      [] ->
        []

      dirs ->
        dirs
        |> Enum.flat_map(&BeamProfile.build_all/1)
        |> Enum.flat_map(&findings_for_profile(&1, dep_name))
    end
  end

  # --- Internals -------------------------------------------------------------

  defp ebin_dirs(dep_name, project_path) do
    name = to_string(dep_name)

    [project_path, "_build", "*", "lib", name, "ebin"]
    |> Path.join()
    |> Path.wildcard()
    |> Enum.filter(&File.dir?/1)
  end

  defp findings_for_profile(%BeamProfile{} = profile, dep_name) do
    imports_findings(profile, dep_name) ++
      handle_undefined_findings(profile, dep_name)
  end

  defp imports_findings(%BeamProfile{imports: imports} = profile, dep_name) do
    imports
    |> Enum.uniq()
    |> Enum.flat_map(fn {mod, func, arity} ->
      classify_import(mod, func, arity, profile, dep_name)
    end)
  end

  defp classify_import(mod, func, arity, profile, dep_name) do
    cond do
      Map.has_key?(@wildcard_modules, mod) ->
        desc = Map.fetch!(@wildcard_modules, mod)

        [
          %Finding{
            dep_name: dep_name,
            file_path: profile.path,
            line: 1,
            check_id: :beam_imports,
            category: @category,
            severity: :critical,
            compile_time?: false,
            description:
              "BEAM #{format_module(profile.module)} imports #{inspect(mod)}.#{func}/#{arity} — #{desc}"
          }
        ]

      Map.has_key?(@specific_imports, {mod, func}) ->
        desc = Map.fetch!(@specific_imports, {mod, func})

        severity =
          if MapSet.member?(@warning_imports, {mod, func}) do
            :warning
          else
            :critical
          end

        [
          %Finding{
            dep_name: dep_name,
            file_path: profile.path,
            line: 1,
            check_id: :beam_imports,
            category: @category,
            severity: severity,
            compile_time?: false,
            description:
              "BEAM #{format_module(profile.module)} imports #{inspect(mod)}.#{func}/#{arity} — #{desc}"
          }
        ]

      true ->
        []
    end
  end

  defp handle_undefined_findings(%BeamProfile{handle_undefined_function?: false}, _), do: []

  defp handle_undefined_findings(%BeamProfile{} = profile, dep_name) do
    [
      %Finding{
        dep_name: dep_name,
        file_path: profile.path,
        line: 1,
        check_id: :beam_handle_undefined_function,
        category: @category,
        severity: :critical,
        compile_time?: false,
        description:
          "BEAM #{format_module(profile.module)} exports $handle_undefined_function/2 — " <>
            "intercepts every undefined call, can route to arbitrary behavior with no static signature"
      }
    ]
  end

  defp format_module(nil), do: "<unknown>"
  defp format_module(mod) when is_atom(mod), do: inspect(mod)

  @doc """
  Returns the full set of `{module, function}` pairs this check flags. Used by
  the coverage test in `test/vet_core/checks/coverage_test.exs` to assert that
  the declared targets are exercised by the sweep.
  """
  def target_patterns do
    wildcard_entries = for {mod, _desc} <- @wildcard_modules, do: {mod, :*}
    specific_entries = Map.keys(@specific_imports)
    wildcard_entries ++ specific_entries
  end
end
