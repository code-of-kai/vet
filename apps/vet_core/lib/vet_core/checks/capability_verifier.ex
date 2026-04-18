defmodule VetCore.Checks.CapabilityVerifier do
  @moduledoc """
  Layer 7 — Capability declaration verifier.

  A package's `mix.exs` can declare what capabilities it legitimately
  needs via `:vet_capabilities`:

      def project do
        [
          app: :my_pkg,
          version: "1.0.0",
          vet_capabilities: [:network, :file_read, :native]
        ]
      end

  This check reads the declared capabilities and compares them against
  the capabilities **observed** from the compiled BEAMs (Layer 1
  imports, Layer 5 native-code artifacts, Layer 3 reflection tripwires).

  Findings fire when:

  - **Undeclared capability in use (critical).** The BEAMs import `:ssh`
    but the package did not declare `:network` or `:ssh`. This is the
    strong direction — anything the code does that the author didn't
    promise.
  - **Declared capability unused (warning).** The author said they need
    `:network` but no BEAM imports a network primitive. Over-declaration
    is a mild anti-signal (asking for more than is needed) but not
    critical; it may be reserved for future use.

  Valid capability atoms:
  `:network, :file_read, :file_write, :system_exec, :code_eval,
  :native, :compile_hook, :reflection, :ssh, :env_access`.

  The verifier is tolerant of missing declarations: a package without
  `:vet_capabilities` produces no findings from this check — the
  existing checks already cover undeclared packages. The intent is to
  make declaration *opt-in pay-off*: a declared package gets richer
  diffing (any undeclared call is an incident) without penalizing
  packages that haven't opted in yet.
  """
  use VetCore.Check

  alias VetCore.BEAM.BeamProfile
  alias VetCore.Types.Finding

  @category :capability_mismatch

  @valid_capabilities ~w(
    network file_read file_write system_exec code_eval native compile_hook
    reflection ssh env_access dns
  )a

  # Map an observed MFA to the capability it implies. Used to decide
  # whether an import is covered by the declared set.
  @capability_for_mfa %{
    {:ssh, :*} => [:ssh, :network],
    {:ssh_sftp, :*} => [:ssh, :network],
    {:ssh_connection, :*} => [:ssh, :network],
    {:ssh_sftpd, :*} => [:ssh, :network],
    {:ftp, :*} => [:network],
    {:httpd, :*} => [:network],
    {:httpc, :*} => [:network],
    {:inets, :*} => [:network],
    {:gen_tcp, :*} => [:network],
    {:gen_udp, :*} => [:network],
    {:gen_sctp, :*} => [:network],
    {:ssl, :*} => [:network],
    {:socket, :*} => [:network],
    {:inet_res, :*} => [:dns, :network],
    {:prim_file, :*} => [:file_read, :file_write],
    {:file, :*} => [:file_read, :file_write],
    {:os, :cmd} => [:system_exec],
    {:erlang, :open_port} => [:system_exec],
    {:erlang, :spawn_executable} => [:system_exec],
    {:erlang, :load_nif} => [:native],
    {:erl_eval, :*} => [:code_eval],
    {:epp, :*} => [:code_eval, :file_read]
  }

  @impl true
  def run(%{name: dep_name} = _dep, project_path, _state) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    case read_declared(dep_dir) do
      :undeclared ->
        []

      {:ok, declared} ->
        observed = observe_capabilities(dep_name, dep_dir, project_path)
        compare(declared, observed, dep_name, dep_dir)
    end
  end

  # --- Reading declared capabilities from mix.exs ---------------------------

  @doc false
  def read_declared(dep_dir) do
    mix_path = Path.join(dep_dir, "mix.exs")

    with true <- File.regular?(mix_path),
         {:ok, source} <- File.read(mix_path),
         {:ok, ast} <- Code.string_to_quoted(source),
         caps when is_list(caps) <- extract_declared(ast) do
      {:ok, MapSet.new(caps)}
    else
      _ -> :undeclared
    end
  end

  defp extract_declared(ast) do
    {_, found} =
      Macro.prewalk(ast, nil, fn
        {:vet_capabilities, _meta, nil}, _acc ->
          {nil, nil}

        {{:vet_capabilities, _}, _, _}, acc ->
          {nil, acc}

        # Match: vet_capabilities: [:a, :b]
        {:vet_capabilities, list} = node, _acc when is_list(list) ->
          {node, capability_list(list)}

        # Match as keyword-style tuple in a list: {:vet_capabilities, [:a, :b]}
        {:vet_capabilities, _meta, [list]} = node, _acc when is_list(list) ->
          {node, capability_list(list)}

        node, acc ->
          {node, acc}
      end)

    found
  end

  defp capability_list(list) when is_list(list) do
    Enum.flat_map(list, fn
      atom when is_atom(atom) -> [atom]
      _ -> []
    end)
  end

  # --- Observing capabilities from compiled BEAMs ---------------------------

  defp observe_capabilities(dep_name, dep_dir, project_path) do
    imports = all_imports(dep_name, project_path)
    native? = has_native_artifact?(dep_dir)

    MapSet.union(
      capabilities_from_imports(imports),
      if(native?, do: MapSet.new([:native]), else: MapSet.new())
    )
  end

  defp all_imports(dep_name, project_path) do
    name = to_string(dep_name)

    [project_path, "_build", "*", "lib", name, "ebin"]
    |> Path.join()
    |> Path.wildcard()
    |> Enum.filter(&File.dir?/1)
    |> Enum.flat_map(&BeamProfile.build_all/1)
    |> Enum.flat_map(fn %BeamProfile{imports: imps} -> imps end)
  end

  defp capabilities_from_imports(imports) do
    Enum.reduce(imports, MapSet.new(), fn {mod, func, _arity}, acc ->
      lookup_caps(mod, func)
      |> Enum.reduce(acc, &MapSet.put(&2, &1))
    end)
  end

  defp lookup_caps(mod, func) do
    Map.get(@capability_for_mfa, {mod, :*}, []) ++
      Map.get(@capability_for_mfa, {mod, func}, [])
  end

  defp has_native_artifact?(dep_dir) do
    priv = Path.join(dep_dir, "priv")

    if File.dir?(priv) do
      priv
      |> Path.join("**/*")
      |> Path.wildcard()
      |> Enum.any?(fn path ->
        File.regular?(path) and Path.extname(path) in [".so", ".dylib", ".dll"]
      end)
    else
      false
    end
  end

  # --- Comparing declared vs observed ---------------------------------------

  defp compare(declared, observed, dep_name, dep_dir) do
    mix_path = Path.join(dep_dir, "mix.exs")

    # Invalid declarations are a warning themselves
    invalid = MapSet.difference(declared, MapSet.new(@valid_capabilities))

    # Capabilities used without being declared — the big one
    undeclared_used = MapSet.difference(observed, declared)
    # Capabilities declared but never used — mild smell
    declared_unused = MapSet.difference(declared, observed) |> MapSet.difference(invalid)

    undeclared_findings =
      Enum.map(undeclared_used, fn cap ->
        %Finding{
          dep_name: dep_name,
          file_path: mix_path,
          line: 1,
          check_id: :capability_undeclared_use,
          category: @category,
          severity: :critical,
          compile_time?: false,
          description:
            "Package uses capability #{inspect(cap)} but does not declare it in " <>
              ":vet_capabilities — observed in compiled BEAMs but not in manifest"
        }
      end)

    unused_findings =
      Enum.map(declared_unused, fn cap ->
        %Finding{
          dep_name: dep_name,
          file_path: mix_path,
          line: 1,
          check_id: :capability_declared_unused,
          category: @category,
          severity: :warning,
          compile_time?: false,
          description:
            "Package declares capability #{inspect(cap)} in :vet_capabilities but " <>
              "does not actually use it — over-declaration is a mild anti-signal"
        }
      end)

    invalid_findings =
      Enum.map(invalid, fn cap ->
        %Finding{
          dep_name: dep_name,
          file_path: mix_path,
          line: 1,
          check_id: :capability_unknown,
          category: @category,
          severity: :warning,
          compile_time?: false,
          description:
            "Package declares unknown capability #{inspect(cap)} in :vet_capabilities — " <>
              "valid values: #{inspect(@valid_capabilities)}"
        }
      end)

    undeclared_findings ++ unused_findings ++ invalid_findings
  end

  @doc """
  Return the list of valid capability atoms. Exposed for test coverage.
  """
  @spec valid_capabilities() :: [atom()]
  def valid_capabilities, do: @valid_capabilities
end
