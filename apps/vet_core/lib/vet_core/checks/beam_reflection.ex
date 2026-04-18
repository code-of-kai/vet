defmodule VetCore.Checks.BeamReflection do
  @moduledoc """
  Layer 3 — Reflection tripwires at the BEAM level.

  Reflection primitives are the "go anywhere" instructions of the BEAM:

  - `apply/3` with non-literal module/function — call anything by atom.
  - `String.to_atom/1`, `:erlang.binary_to_atom/1` — manufacture module
    or function names from arbitrary input.
  - `:erlang.binary_to_term/1` — deserialize a term, including function
    references and tuples that drive `apply/3`.
  - `$handle_undefined_function/2` — intercept every undefined call.
  - Raw dynamic-dispatch BEAM opcodes — `:apply`, `:apply_last`,
    `:call_fun`, `:call_fun2`.

  Each is individually legitimate (parsing, RPC dispatch, plug-in
  systems). Weighted on its own, none deserves a critical finding. But
  a malicious package can use them to make static analysis blind:
  every other Vet check is an analysis of *which* call is being made,
  and reflection primitives turn "which" into "decided at runtime."

  This check counts the tripwires per module and fires:

  - **Critical** when a module exports `$handle_undefined_function/2` —
    every undefined call is interceptable.
  - **Critical** when a module imports `:erlang.binary_to_term/1,2`
    *and* has dynamic dispatch instructions — encoded payloads can drive
    arbitrary calls.
  - **Warning** when a single module has ≥ 5 distinct reflection imports
    *or* ≥ 15 dynamic dispatch instructions — high density.

  Modules under both thresholds emit nothing. Per-module info-level
  noise was deliberately removed: a single `apply/3` call is so
  ubiquitous in real Elixir code (Plug, Phoenix, Ecto, GenServer
  callbacks all dispatch dynamically) that flagging it on every module
  drowns the genuine signal.

  Working at the BEAM layer means defdelegate, atom-aliased calls,
  `.erl` source, and macro-synthesized calls all surface.
  """
  use VetCore.Check

  alias VetCore.BEAM.BeamProfile
  alias VetCore.Types.Finding

  @category :reflection

  # MFA tuples that constitute reflection primitives. Each lives in this
  # set as `{module_atom_or_alias, function, arity}`. Elixir aliases are
  # represented as their underlying atom (e.g. `String` is the atom
  # `:"Elixir.String"` in the BEAM import table).
  @reflection_mfas MapSet.new([
                     # Atom synthesis
                     {String, :to_atom, 1},
                     {String, :to_existing_atom, 1},
                     {:erlang, :binary_to_atom, 1},
                     {:erlang, :binary_to_atom, 2},
                     {:erlang, :binary_to_existing_atom, 1},
                     {:erlang, :binary_to_existing_atom, 2},
                     {:erlang, :list_to_atom, 1},
                     {:erlang, :list_to_existing_atom, 1},
                     # Term decoding
                     {:erlang, :binary_to_term, 1},
                     {:erlang, :binary_to_term, 2},
                     # Dynamic dispatch primitives
                     {:erlang, :apply, 2},
                     {:erlang, :apply, 3},
                     {:erlang, :make_fun, 3},
                     {Kernel, :apply, 2},
                     {Kernel, :apply, 3},
                     # Function reference construction
                     {:erlang, :fun_info, 1},
                     {:erlang, :fun_info, 2}
                   ])

  # `binary_to_term/1,2` — paired with dispatch, this is decode-and-call.
  @term_decoders MapSet.new([
                   {:erlang, :binary_to_term, 1},
                   {:erlang, :binary_to_term, 2}
                 ])

  @density_imports_threshold 5
  @density_dispatch_threshold 15

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
    reflection_imports = reflection_imports_for(profile)
    dispatch_count = profile.dynamic_dispatch_count

    handle_undef_findings(profile, dep_name) ++
      decode_and_dispatch_findings(profile, reflection_imports, dispatch_count, dep_name) ++
      density_findings(profile, reflection_imports, dispatch_count, dep_name)
  end

  defp reflection_imports_for(%BeamProfile{imports: imports}) do
    Enum.filter(imports, fn mfa -> MapSet.member?(@reflection_mfas, mfa) end)
  end

  defp handle_undef_findings(%BeamProfile{handle_undefined_function?: false}, _), do: []

  defp handle_undef_findings(%BeamProfile{} = profile, dep_name) do
    [
      %Finding{
        dep_name: dep_name,
        file_path: profile.path,
        line: 1,
        check_id: :reflection_handle_undefined,
        category: @category,
        severity: :critical,
        compile_time?: false,
        description:
          "BEAM #{inspect(profile.module)} exports $handle_undefined_function/2 — " <>
            "intercepts every undefined call; a static analyzer cannot enumerate " <>
            "what the module actually responds to"
      }
    ]
  end

  defp decode_and_dispatch_findings(%BeamProfile{} = profile, reflection_imports, dispatch_count, dep_name) do
    has_decoder? = Enum.any?(reflection_imports, &MapSet.member?(@term_decoders, &1))
    has_dispatch? = dispatch_count > 0 or has_apply?(reflection_imports)

    if has_decoder? and has_dispatch? do
      [
        %Finding{
          dep_name: dep_name,
          file_path: profile.path,
          line: 1,
          check_id: :reflection_decode_and_dispatch,
          category: @category,
          severity: :critical,
          compile_time?: false,
          description:
            "BEAM #{inspect(profile.module)} pairs :erlang.binary_to_term with dynamic " <>
              "dispatch — encoded binary payloads can be deserialized into MFA tuples " <>
              "and executed (decode-and-call pattern)"
        }
      ]
    else
      []
    end
  end

  defp has_apply?(reflection_imports) do
    Enum.any?(reflection_imports, fn
      {:erlang, :apply, _} -> true
      {Kernel, :apply, _} -> true
      _ -> false
    end)
  end

  defp density_findings(%BeamProfile{} = profile, reflection_imports, dispatch_count, dep_name) do
    distinct = reflection_imports |> Enum.uniq() |> length()

    cond do
      distinct >= @density_imports_threshold and dispatch_count >= @density_dispatch_threshold ->
        [density_finding(profile, dep_name, distinct, dispatch_count, :critical)]

      distinct >= @density_imports_threshold or dispatch_count >= @density_dispatch_threshold ->
        [density_finding(profile, dep_name, distinct, dispatch_count, :warning)]

      true ->
        []
    end
  end

  defp density_finding(profile, dep_name, distinct, dispatch_count, severity) do
    %Finding{
      dep_name: dep_name,
      file_path: profile.path,
      line: 1,
      check_id: :reflection_density,
      category: @category,
      severity: severity,
      compile_time?: false,
      description:
        "BEAM #{inspect(profile.module)} has #{distinct} reflection import(s) " <>
          "and #{dispatch_count} dynamic-dispatch instruction(s) — " <>
          density_explanation(distinct, dispatch_count)
    }
  end

  defp density_explanation(0, count), do: "raw dispatch count: #{count}"
  defp density_explanation(distinct, 0), do: "reflection imports: #{distinct}"

  defp density_explanation(distinct, dispatch),
    do:
      "#{distinct} reflection imports plus #{dispatch} dispatch instructions — " <>
        "high reflection surface, harder to statically reason about"
end
