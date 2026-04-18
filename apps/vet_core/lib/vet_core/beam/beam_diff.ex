defmodule VetCore.BEAM.BeamDiff do
  @moduledoc """
  Compare two `VetCore.BEAM.BeamProfile` snapshots — typically the same
  module compiled from two different versions of a package.

  The point of a BEAM-level diff is to catch security profile shifts that
  source-level diffing misses: an `.erl` file added, a defdelegate target
  flipped to `:ssh`, atom-aliased calls activated for the first time, a
  `$handle_undefined_function/2` newly exported, a dynamic-dispatch
  instruction count that doubled.

  None of these can be hidden from this layer because the BEAM has the
  literal call wired in regardless of how the source was spelled.
  """

  alias VetCore.BEAM.BeamProfile

  defstruct [
    :module,
    :old_path,
    :new_path,
    imports_added: [],
    imports_removed: [],
    exports_added: [],
    exports_removed: [],
    atoms_added: [],
    atoms_removed: [],
    dynamic_dispatch_delta: 0,
    handle_undefined_function_added?: false,
    handle_undefined_function_removed?: false
  ]

  @type t :: %__MODULE__{
          module: atom() | nil,
          old_path: String.t() | nil,
          new_path: String.t() | nil,
          imports_added: [BeamProfile.mfa_tuple()],
          imports_removed: [BeamProfile.mfa_tuple()],
          exports_added: [{atom(), non_neg_integer()}],
          exports_removed: [{atom(), non_neg_integer()}],
          atoms_added: [atom()],
          atoms_removed: [atom()],
          dynamic_dispatch_delta: integer(),
          handle_undefined_function_added?: boolean(),
          handle_undefined_function_removed?: boolean()
        }

  @type module_set_diff :: %{
          added_modules: [BeamProfile.t()],
          removed_modules: [BeamProfile.t()],
          changed_modules: [t()]
        }

  @doc """
  Diff two `BeamProfile` snapshots of (presumably) the same module.

  Returns a `BeamDiff` struct. If there are no changes, every collection
  field will be empty and counter fields will be zero.
  """
  @spec diff(BeamProfile.t(), BeamProfile.t()) :: t()
  def diff(%BeamProfile{} = old, %BeamProfile{} = new) do
    old_imports = MapSet.new(old.imports)
    new_imports = MapSet.new(new.imports)
    old_exports = MapSet.new(old.exports)
    new_exports = MapSet.new(new.exports)
    old_atoms = MapSet.new(old.atoms)
    new_atoms = MapSet.new(new.atoms)

    %__MODULE__{
      module: new.module || old.module,
      old_path: old.path,
      new_path: new.path,
      imports_added: MapSet.difference(new_imports, old_imports) |> MapSet.to_list(),
      imports_removed: MapSet.difference(old_imports, new_imports) |> MapSet.to_list(),
      exports_added: MapSet.difference(new_exports, old_exports) |> MapSet.to_list(),
      exports_removed: MapSet.difference(old_exports, new_exports) |> MapSet.to_list(),
      atoms_added: MapSet.difference(new_atoms, old_atoms) |> MapSet.to_list(),
      atoms_removed: MapSet.difference(old_atoms, new_atoms) |> MapSet.to_list(),
      dynamic_dispatch_delta: new.dynamic_dispatch_count - old.dynamic_dispatch_count,
      handle_undefined_function_added?:
        new.handle_undefined_function? and not old.handle_undefined_function?,
      handle_undefined_function_removed?:
        old.handle_undefined_function? and not new.handle_undefined_function?
    }
  end

  @doc """
  Diff two complete profile sets (e.g., two `_build/.../ebin` directories).

  Returns a map with `:added_modules`, `:removed_modules`, and
  `:changed_modules` (a list of `BeamDiff.t()` for modules whose profile
  changed).
  """
  @spec diff_set([BeamProfile.t()], [BeamProfile.t()]) :: module_set_diff()
  def diff_set(old_profiles, new_profiles) when is_list(old_profiles) and is_list(new_profiles) do
    old_by_module = Map.new(old_profiles, &{&1.module, &1})
    new_by_module = Map.new(new_profiles, &{&1.module, &1})

    old_modules = MapSet.new(Map.keys(old_by_module))
    new_modules = MapSet.new(Map.keys(new_by_module))

    added_keys = MapSet.difference(new_modules, old_modules) |> MapSet.to_list()
    removed_keys = MapSet.difference(old_modules, new_modules) |> MapSet.to_list()
    common_keys = MapSet.intersection(old_modules, new_modules) |> MapSet.to_list()

    changed =
      Enum.flat_map(common_keys, fn module ->
        old = Map.fetch!(old_by_module, module)
        new = Map.fetch!(new_by_module, module)
        d = diff(old, new)
        if changed?(d), do: [d], else: []
      end)

    %{
      added_modules: Enum.map(added_keys, &Map.fetch!(new_by_module, &1)),
      removed_modules: Enum.map(removed_keys, &Map.fetch!(old_by_module, &1)),
      changed_modules: changed
    }
  end

  @doc """
  Classify a `BeamDiff` for suspicious changes that warrant a finding.

  Returns `{suspicious?, signals}` where `signals` is a list of atoms
  describing what changed. Possible signals:

  - `:dangerous_imports_added` — new import of an MFA in the dangerous set
  - `:handle_undefined_function_added` — module newly exports
    `$handle_undefined_function/2`
  - `:dynamic_dispatch_spike` — dynamic dispatch instructions increased
    by ≥3 (configurable threshold)
  - `:suspicious_atoms_added` — new URL/IP/hostname-shaped atoms appeared
  """
  @spec classify(t(), keyword()) :: {boolean(), [atom()]}
  def classify(%__MODULE__{} = diff, opts \\ []) do
    dispatch_threshold = Keyword.get(opts, :dispatch_threshold, 3)

    signals =
      []
      |> maybe_signal(dangerous_imports_added?(diff), :dangerous_imports_added)
      |> maybe_signal(diff.handle_undefined_function_added?, :handle_undefined_function_added)
      |> maybe_signal(
        diff.dynamic_dispatch_delta >= dispatch_threshold,
        :dynamic_dispatch_spike
      )
      |> maybe_signal(suspicious_atoms_added?(diff), :suspicious_atoms_added)

    {signals != [], Enum.reverse(signals)}
  end

  @doc """
  Returns `true` if the diff contains any change at all.
  """
  @spec changed?(t()) :: boolean()
  def changed?(%__MODULE__{} = d) do
    d.imports_added != [] or
      d.imports_removed != [] or
      d.exports_added != [] or
      d.exports_removed != [] or
      d.atoms_added != [] or
      d.atoms_removed != [] or
      d.dynamic_dispatch_delta != 0 or
      d.handle_undefined_function_added? or
      d.handle_undefined_function_removed?
  end

  # --- Internals -------------------------------------------------------------

  # Dangerous wildcard modules — every newly imported MFA from one of these
  # is a critical signal. Mirrors `VetCore.Checks.BeamImports`.
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

  defp dangerous_imports_added?(%__MODULE__{imports_added: imports}) do
    Enum.any?(imports, &dangerous_mfa?/1)
  end

  defp dangerous_mfa?({mod, func, _arity}) do
    MapSet.member?(@dangerous_modules, mod) or
      MapSet.member?(@dangerous_mfas, {mod, func})
  end

  @url_re ~r/^https?:\/\//
  @ipv4_re ~r/^\d{1,3}(\.\d{1,3}){3}$/
  @hostname_re ~r/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/

  defp suspicious_atoms_added?(%__MODULE__{atoms_added: atoms}) do
    Enum.any?(atoms, &suspicious_atom?/1)
  end

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

  defp maybe_signal(signals, true, signal), do: [signal | signals]
  defp maybe_signal(signals, _false, _signal), do: signals
end
