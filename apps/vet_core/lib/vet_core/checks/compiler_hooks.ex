defmodule VetCore.Checks.CompilerHooks do
  @moduledoc """
  Detects compile-time hooks (`@before_compile`, `@after_compile`,
  `@external_resource`, `Mix.compilers/0`, custom mix.exs compilers).

  Hook *presence* is not the danger — every Phoenix, Ecto, Gettext, and
  LiveView module wires `@before_compile`. The danger is what the hooked
  callback *does* during `mix deps.compile`.

  This check therefore pre-indexes every `__before_compile__/1` and
  `__after_compile__/2` definition inside the package. For each
  `@before_compile <Target>` / `@after_compile <Target>` it:

    * Resolves `<Target>` to a module — handling aliases and `__MODULE__` —
      and looks the callback body up in the index.
    * If the callback body contains compile-time-dangerous calls
      (`System.cmd`, `Code.eval_*`, `:erlang.binary_to_term`, `Port.open`,
      HTTP clients), fires `:critical`.
    * If the callback is found but the body is "safe AST construction"
      (just `quote do def ... end` codegen with no dangerous calls), fires
      no finding — that is what every framework does.
    * If the target is external / unfound (the callback lives in a
      different package or is generated dynamically), fires `:warning` —
      we cannot statically inspect it, but the user should know a hook
      exists.

  `Mix.compilers/0` and custom `compilers:` entries in `mix.exs` remain
  `:critical`: those reshape the compiler pipeline itself rather than
  hooking into a known-shape extension point.
  """
  use VetCore.Check

  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    files = FileHelper.read_and_parse(dep_name, project_path)
    callback_index = build_callback_index(files)

    Enum.flat_map(files, fn {file_path, source, ast} ->
      walk_file(ast, dep_name, file_path, source, callback_index)
    end)
  end

  # ------------------------------------------------------------------
  # Pre-pass: index callback bodies defined anywhere in this package.
  # ------------------------------------------------------------------

  defp build_callback_index(files) do
    Enum.reduce(files, %{}, fn {_file, _source, ast}, acc ->
      walk_modules(ast, acc, fn module_segments, body, acc ->
        callbacks = find_callbacks_in_module_body(body)

        if map_size(callbacks) > 0 do
          Map.update(acc, module_segments, callbacks, &Map.merge(&1, callbacks))
        else
          acc
        end
      end)
    end)
  end

  # Walk the AST, calling `fun.(module_segments, module_body, acc)` for every
  # `defmodule` encountered.
  defp walk_modules(ast, acc, fun) do
    {_, result} =
      Macro.prewalk(ast, acc, fn
        {:defmodule, _meta, [{:__aliases__, _, segments}, [do: body]]} = node, acc
        when is_list(segments) ->
          {node, fun.(segments, body, acc)}

        node, acc ->
          {node, acc}
      end)

    result
  end

  defp find_callbacks_in_module_body(body) do
    {_, result} =
      Macro.prewalk(body, %{}, fn
        # Conventional macro form
        {form, _meta, [{:__before_compile__, _, args}, [do: cb_body]]} = node, acc
        when form in [:defmacro, :defmacrop] and is_list(args) ->
          {node, Map.put(acc, :before_compile, cb_body)}

        # Function form (some packages use def for the callback)
        {form, _meta, [{:__before_compile__, _, args}, [do: cb_body]]} = node, acc
        when form in [:def, :defp] and is_list(args) ->
          {node, Map.put(acc, :before_compile, cb_body)}

        {form, _meta, [{:__after_compile__, _, args}, [do: cb_body]]} = node, acc
        when form in [:defmacro, :defmacrop] and is_list(args) ->
          {node, Map.put(acc, :after_compile, cb_body)}

        {form, _meta, [{:__after_compile__, _, args}, [do: cb_body]]} = node, acc
        when form in [:def, :defp] and is_list(args) ->
          {node, Map.put(acc, :after_compile, cb_body)}

        node, acc ->
          {node, acc}
      end)

    result
  end

  # ------------------------------------------------------------------
  # Per-file walk — knows the enclosing defmodule when matching attrs.
  # ------------------------------------------------------------------

  defp walk_file(ast, dep_name, file_path, source, callback_index) do
    walk_modules(ast, [], fn module_segments, body, acc ->
      findings = scan_module_body(body, module_segments, dep_name, file_path, source, callback_index)
      acc ++ findings
    end) ++ scan_top_level(ast, dep_name, file_path, source)
  end

  # Inside a defmodule body, find @before_compile / @after_compile / @external_resource.
  defp scan_module_body(body, module_segments, dep_name, file_path, source, callback_index) do
    {_, findings} =
      Macro.prewalk(body, [], fn
        {:@, meta, [{:before_compile, _, [target]}]} = node, acc ->
          finding =
            classify_hook(
              :before_compile,
              target,
              meta,
              module_segments,
              dep_name,
              file_path,
              source,
              callback_index
            )

          {node, prepend(finding, acc)}

        {:@, meta, [{:after_compile, _, [target]}]} = node, acc ->
          finding =
            classify_hook(
              :after_compile,
              target,
              meta,
              module_segments,
              dep_name,
              file_path,
              source,
              callback_index
            )

          {node, prepend(finding, acc)}

        {:@, meta, [{:external_resource, _, _}]} = node, acc ->
          # @external_resource is a passive recompilation hint — it tells the
          # compiler to invalidate the BEAM if the file changes, nothing more.
          # The actual file read (the dangerous bit, if any) is independently
          # caught by file_access. Surface the surface area as :info so the
          # user can audit it, but don't double-count it as a CT warning.
          finding =
            build_finding(
              "@external_resource — recompilation hint for an external file",
              :info,
              meta,
              dep_name,
              file_path,
              source
            )

          {node, [finding | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(findings)
  end

  # mix.exs-level patterns (Mix.compilers, custom compilers) reshape the
  # compilation pipeline. They are only compile-time-critical when they appear
  # in `mix.exs` itself — the same call inside a function body in a runtime
  # module (e.g. Phoenix.CodeReloader.Server.mix_compile/4) is runtime use of
  # Mix tooling, not a hook on the project's compiler chain.
  defp scan_top_level(_ast, _dep_name, file_path, _source)
       when not is_binary(file_path),
       do: []

  defp scan_top_level(ast, dep_name, file_path, source) do
    if Path.basename(file_path) == "mix.exs" do
      scan_mix_exs(ast, dep_name, file_path, source)
    else
      []
    end
  end

  defp scan_mix_exs(ast, dep_name, file_path, source) do
    {_, findings} =
      Macro.prewalk(ast, [], fn
        # Mix.compilers() — fully-qualified.
        {{:., _, [{:__aliases__, _, [:Mix]}, :compilers]}, meta, _args} = node, acc ->
          finding =
            build_finding(
              "Mix.compilers() usage — may customize the compilation pipeline",
              :critical,
              meta,
              dep_name,
              file_path,
              source
            )

          {node, [finding | acc]}

        # `compilers: [...]` in a project keyword list.
        {:compilers, meta, [[_ | _] = _compilers]} = node, acc ->
          finding =
            build_finding(
              "Custom compilers defined in mix.exs — may execute arbitrary code during compilation",
              :critical,
              meta,
              dep_name,
              file_path,
              source
            )

          {node, [finding | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(findings)
  end

  defp prepend(nil, acc), do: acc
  defp prepend(finding, acc), do: [finding | acc]

  # ------------------------------------------------------------------
  # Hook classification — the smart bit.
  # ------------------------------------------------------------------

  defp classify_hook(kind, target, meta, current_module, dep_name, file_path, source, callback_index) do
    target_segments = resolve_hook_target(target, current_module)

    case lookup_callback_body(target_segments, kind, callback_index) do
      :external ->
        build_finding(
          "@#{kind} #{format_target(target_segments)} — callback runs at compile time " <>
            "(target callback not found in this package; can't statically inspect)",
          :warning,
          meta,
          dep_name,
          file_path,
          source
        )

      {:found, body} ->
        if dangerous_compile_time_call?(body) do
          build_finding(
            "@#{kind} #{format_target(target_segments)} — callback contains compile-time-dangerous calls " <>
              "(System.cmd / Code.eval / binary_to_term / network)",
            :critical,
            meta,
            dep_name,
            file_path,
            source
          )
        else
          # Safe AST-construction macro — what every framework does. No finding.
          nil
        end
    end
  end

  defp lookup_callback_body(nil, _kind, _index), do: :external

  defp lookup_callback_body(segments, kind, index) do
    case Map.get(index, segments) do
      nil ->
        :external

      callbacks ->
        case Map.get(callbacks, kind) do
          nil -> :external
          body -> {:found, body}
        end
    end
  end

  # @before_compile MyMod                  -> [:MyMod]
  # @before_compile {MyMod, :func}         -> [:MyMod] (we only index the conventional callback)
  # @before_compile :erlang_atom           -> [:erlang_atom]
  # @before_compile __MODULE__             -> the current module's segments
  # @before_compile unquote(__MODULE__)    -> the current module (common inside defmacro __using__)
  defp resolve_hook_target({:unquote, _, [inner]}, current_module),
    do: resolve_hook_target(inner, current_module)

  defp resolve_hook_target({:__MODULE__, _, _}, current_module), do: current_module

  defp resolve_hook_target({:__aliases__, _, segments}, _current_module) when is_list(segments),
    do: segments

  defp resolve_hook_target({{:__aliases__, _, segments}, func}, _current_module)
       when is_list(segments) and is_atom(func),
       do: segments

  defp resolve_hook_target({{:__MODULE__, _, _}, func}, current_module) when is_atom(func),
    do: current_module

  defp resolve_hook_target(target, _current_module)
       when is_atom(target) and target not in [nil, true, false],
       do: [target]

  defp resolve_hook_target(_, _), do: nil

  defp format_target(nil), do: "<unknown>"

  defp format_target(segments) when is_list(segments) do
    segments
    |> Enum.map(&Atom.to_string/1)
    |> Enum.join(".")
  end

  # ------------------------------------------------------------------
  # Body inspection — does the callback do something genuinely scary?
  # ------------------------------------------------------------------

  @doc false
  def dangerous_compile_time_call?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        node, true -> {node, true}
        node, false -> {node, dangerous_node?(node)}
      end)

    found
  end

  defp dangerous_node?(node) do
    case node do
      # System.cmd / System.shell / :os.cmd
      {{:., _, [{:__aliases__, _, [:System]}, fn_name]}, _, _}
      when fn_name in [:cmd, :shell] ->
        true

      {{:., _, [:os, :cmd]}, _, _} ->
        true

      # Runtime code evaluation / compilation
      {{:., _, [{:__aliases__, _, [:Code]}, fn_name]}, _, _}
      when fn_name in [
             :eval_string,
             :eval_quoted,
             :eval_file,
             :compile_string,
             :compile_quoted,
             :compile_file,
             :require_file
           ] ->
        true

      {{:., _, [{:__aliases__, _, [:EEx]}, fn_name]}, _, _}
      when fn_name in [:eval_string, :eval_file, :compile_string, :compile_file] ->
        true

      # Term deserialization (decode-and-call vector)
      {{:., _, [:erlang, :binary_to_term]}, _, _} ->
        true

      # Port / executable spawn
      {{:., _, [{:__aliases__, _, [:Port]}, :open]}, _, _} ->
        true

      {{:., _, [:erlang, :open_port]}, _, _} ->
        true

      {{:., _, [:erlang, :spawn_executable]}, _, _} ->
        true

      # Module.create — synthesize a module from raw quoted form at runtime
      {{:., _, [{:__aliases__, _, [:Module]}, :create]}, _, _} ->
        true

      # HTTP client libraries (network exfil during compile)
      {{:., _, [{:__aliases__, _, [http_mod]}, _fn]}, _, _}
      when http_mod in [:Req, :HTTPoison, :Finch, :Tesla, :Mojito] ->
        true

      {{:., _, [:httpc, _]}, _, _} ->
        true

      {{:., _, [:gen_tcp, :connect]}, _, _} ->
        true

      {{:., _, [:ssl, :connect]}, _, _} ->
        true

      _ ->
        false
    end
  end

  # ------------------------------------------------------------------
  # Finding helper
  # ------------------------------------------------------------------

  defp build_finding(description, severity, meta, dep_name, file_path, source) do
    line = meta[:line] || 0

    %Finding{
      dep_name: dep_name,
      file_path: file_path,
      line: line,
      column: meta[:column],
      check_id: :compiler_hooks,
      category: :compiler_hooks,
      severity: severity,
      compile_time?: true,
      snippet: FileHelper.snippet(source, line),
      description: description
    }
  end
end
