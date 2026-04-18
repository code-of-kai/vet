defmodule VetCore.Checks.BeamDelta do
  @moduledoc """
  Layer 4 — BEAM-level version delta.

  Loads the currently-installed compiled BEAMs for a dependency, compares
  them against the cached `BeamProfile` snapshot of any earlier version
  (from `VetCore.BEAM.ProfileCache`), and fires findings on suspicious
  deltas:

  - New imports of dangerous modules/MFAs (e.g., `:ssh`, `:os.cmd`,
    `:erlang.load_nif/2`).
  - `$handle_undefined_function/2` newly exported.
  - Spike in dynamic dispatch instructions.
  - New URL/IP/hostname-shaped atoms in the atom table.
  - New modules introduced in the package.

  This layer activates only when the cache contains at least one earlier
  version of the same package. The first scan of a package primes the
  cache; the second scan can diff.

  Snapshotting the *current* version into the cache happens at the end of
  the scan, after findings are computed, so the diff always compares
  the new build against the prior cached state.
  """
  use VetCore.Check

  alias VetCore.BEAM.{BeamDiff, BeamProfile, ProfileCache}
  alias VetCore.Types.Finding

  @category :bytecode_version_delta

  @impl true
  def run(%{name: dep_name, version: current_version} = _dep, project_path, _state)
      when is_binary(current_version) do
    current_profiles = current_profiles(dep_name, project_path)

    case prior_version(project_path, dep_name, current_version) do
      nil ->
        []

      prior ->
        prior_profiles = ProfileCache.load(project_path, dep_name, prior)
        diff_findings(prior_profiles, current_profiles, dep_name, prior, current_version)
    end
  end

  def run(_dep, _project_path, _state), do: []

  @doc """
  Snapshot a dep's compiled profiles into the cache. Called by the
  Scanner once per dep after the rest of the pipeline runs.
  """
  @spec snapshot(atom(), String.t() | nil, String.t()) :: :ok
  def snapshot(_dep_name, nil, _project_path), do: :ok

  def snapshot(dep_name, version, project_path) when is_binary(version) do
    profiles = current_profiles(dep_name, project_path)

    if profiles != [] do
      ProfileCache.save(profiles, project_path, dep_name, version)
    end

    :ok
  end

  # --- Internals -------------------------------------------------------------

  defp current_profiles(dep_name, project_path) do
    ebin_dirs(dep_name, project_path)
    |> Enum.flat_map(&BeamProfile.build_all/1)
  end

  defp ebin_dirs(dep_name, project_path) do
    name = to_string(dep_name)

    [project_path, "_build", "*", "lib", name, "ebin"]
    |> Path.join()
    |> Path.wildcard()
    |> Enum.filter(&File.dir?/1)
  end

  # Pick the latest cached version that's not equal to the current one.
  # We prefer the lexically-greatest non-current entry; callers can
  # implement semver-aware selection later if needed.
  defp prior_version(project_path, dep_name, current_version) do
    project_path
    |> ProfileCache.versions(dep_name)
    |> Enum.reject(&(&1 == current_version))
    |> Enum.sort()
    |> List.last()
  end

  defp diff_findings(prior_profiles, current_profiles, dep_name, prior_version, current_version) do
    %{
      added_modules: added,
      removed_modules: _removed,
      changed_modules: changed
    } = BeamDiff.diff_set(prior_profiles, current_profiles)

    changed_findings =
      Enum.flat_map(changed, fn diff ->
        case BeamDiff.classify(diff) do
          {true, signals} ->
            Enum.map(signals, fn signal ->
              build_finding(dep_name, diff, signal, prior_version, current_version)
            end)

          {false, _} ->
            []
        end
      end)

    added_findings =
      Enum.flat_map(added, fn %BeamProfile{} = profile ->
        build_added_module_findings(dep_name, profile, prior_version, current_version)
      end)

    changed_findings ++ added_findings
  end

  defp build_finding(dep_name, %BeamDiff{} = diff, signal, prior, current) do
    {severity, description} = describe(signal, diff, prior, current)

    %Finding{
      dep_name: dep_name,
      file_path: diff.new_path || diff.old_path || "<unknown>",
      line: 1,
      check_id: signal_to_check_id(signal),
      category: @category,
      severity: severity,
      compile_time?: false,
      description: description
    }
  end

  defp build_added_module_findings(dep_name, %BeamProfile{} = profile, prior, current) do
    base = [
      %Finding{
        dep_name: dep_name,
        file_path: profile.path,
        line: 1,
        check_id: :beam_delta_module_added,
        category: @category,
        severity: :warning,
        compile_time?: false,
        description:
          "Module #{inspect(profile.module)} appeared in #{current} that was not in #{prior} — " <>
            "new module added across versions"
      }
    ]

    # If the brand-new module already imports something dangerous, also
    # treat that as a delta-driven import finding so the user sees it
    # surfaced as a transition rather than just a Layer 1 import.
    dangerous_in_new =
      profile.imports
      |> Enum.uniq()
      |> Enum.filter(fn {mod, func, _arity} -> dangerous?(mod, func) end)

    extra =
      Enum.map(dangerous_in_new, fn {mod, func, arity} ->
        %Finding{
          dep_name: dep_name,
          file_path: profile.path,
          line: 1,
          check_id: :beam_delta_dangerous_import,
          category: @category,
          severity: :critical,
          compile_time?: false,
          description:
            "Newly-added module #{inspect(profile.module)} in #{current} imports " <>
              "#{inspect(mod)}.#{func}/#{arity} — dangerous capability introduced via new module"
        }
      end)

    base ++ extra
  end

  defp describe(:dangerous_imports_added, %BeamDiff{} = diff, prior, current) do
    examples =
      diff.imports_added
      |> Enum.filter(fn {mod, func, _arity} -> dangerous?(mod, func) end)
      |> Enum.take(3)
      |> Enum.map(fn {m, f, a} -> "#{inspect(m)}.#{f}/#{a}" end)
      |> Enum.join(", ")

    {:critical,
     "Module #{inspect(diff.module)} gained dangerous imports between #{prior} and #{current}: " <>
       examples}
  end

  defp describe(:handle_undefined_function_added, %BeamDiff{} = diff, prior, current) do
    {:critical,
     "Module #{inspect(diff.module)} newly exports $handle_undefined_function/2 in #{current} " <>
       "(absent in #{prior}) — module can now intercept arbitrary undefined calls"}
  end

  defp describe(:dynamic_dispatch_spike, %BeamDiff{} = diff, prior, current) do
    {:warning,
     "Module #{inspect(diff.module)} dynamic-dispatch instruction count increased by " <>
       "#{diff.dynamic_dispatch_delta} between #{prior} and #{current} — " <>
       "more runtime indirection (apply/fun.()), harder to statically analyze"}
  end

  defp describe(:suspicious_atoms_added, %BeamDiff{} = diff, prior, current) do
    examples =
      diff.atoms_added
      |> Enum.filter(&suspicious_atom?/1)
      |> Enum.take(3)
      |> Enum.map(&inspect/1)
      |> Enum.join(", ")

    {:warning,
     "Module #{inspect(diff.module)} gained URL/IP/hostname-shaped atoms between " <>
       "#{prior} and #{current}: #{examples}"}
  end

  defp signal_to_check_id(:dangerous_imports_added), do: :beam_delta_dangerous_import
  defp signal_to_check_id(:handle_undefined_function_added), do: :beam_delta_handle_undefined
  defp signal_to_check_id(:dynamic_dispatch_spike), do: :beam_delta_dispatch_spike
  defp signal_to_check_id(:suspicious_atoms_added), do: :beam_delta_suspicious_atoms

  @dangerous_modules MapSet.new([
                       :ssh,
                       :ssh_sftp,
                       :ssh_connection,
                       :ssh_client_key_api,
                       :ssh_server_key_api,
                       :ssh_sftpd,
                       :ftp,
                       :httpd,
                       :tftp,
                       :inet_res,
                       :prim_file,
                       :erl_eval
                     ])

  @dangerous_mfas MapSet.new([
                    {:os, :cmd},
                    {:erlang, :open_port},
                    {:erlang, :spawn_executable},
                    {:erlang, :load_nif},
                    {:disk_log, :open},
                    {:disk_log, :log},
                    {:disk_log, :blog},
                    {:epp, :scan_file},
                    {:epp, :parse_file},
                    {:epp, :open},
                    {:inets, :start},
                    {:inets, :stop}
                  ])

  defp dangerous?(mod, func) do
    MapSet.member?(@dangerous_modules, mod) or
      MapSet.member?(@dangerous_mfas, {mod, func})
  end

  @url_re ~r/^https?:\/\//
  @ipv4_re ~r/^\d{1,3}(\.\d{1,3}){3}$/
  @hostname_re ~r/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/

  defp suspicious_atom?(atom) when is_atom(atom) do
    str = Atom.to_string(atom)

    cond do
      Regex.match?(@url_re, str) -> true
      Regex.match?(@ipv4_re, str) -> true
      String.contains?(str, ".") and Regex.match?(@hostname_re, str) -> true
      true -> false
    end
  end

  defp suspicious_atom?(_), do: false
end
