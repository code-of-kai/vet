defmodule VetCore.AST.Walker do
  @moduledoc false

  alias VetCore.Types.Finding

  @type context ::
          :module_body
          | :def
          | :defmacro
          | :module_attribute
          | :quote

  @type walker_state :: %{
          file_path: String.t(),
          context_stack: [context()],
          aliases: %{atom() => [atom()]},
          imports: [[atom()]],
          bindings: %{atom() => [atom()]},
          findings: [Finding.t()],
          matchers: [matcher()],
          dep_name: atom()
        }

  @type matcher ::
          (Macro.t(), walker_state() -> Finding.t() | nil)

  @context_openers %{
    :defmodule => :module_body,
    :def => :def,
    :defp => :def,
    :defmacro => :defmacro,
    :defmacrop => :defmacro
  }

  # Dangerous functions we always want to detect, even if the module isn't loaded.
  # This is the fallback for static analysis when modules can't be introspected.
  @dangerous_functions %{
    [:System] => [:cmd, :shell, :find_executable, :get_env, :fetch_env, :fetch_env!],
    [:Code] => [:eval_string, :eval_quoted, :eval_file, :compile_string, :compile_quoted],
    [:File] => [:read!, :write!, :rm, :rm_rf, :cp, :cp_r, :ln_s, :stream!, :open, :mkdir, :mkdir_p],
    [:Port] => [:open],
    [:Module] => [:create],
    [:EEx] => [:eval_string, :eval_file, :compile_string, :compile_file],
    [:Base] => [:decode64, :decode64!],
    [:String] => [:to_atom, :to_existing_atom],
    [:List] => [:to_atom, :to_existing_atom],
    [:IO] => [:puts, :write, :binwrite, :inspect],
    [:Req] => [:get, :get!, :post, :post!, :put, :put!, :delete, :delete!, :request, :request!],
    [:HTTPoison] => [:get, :get!, :post, :post!, :put, :put!, :delete, :delete!, :request, :request!],
    [:Finch] => [:request, :build],
    [:Mint, :HTTP] => [:connect],
    [:Kernel] => [:apply]
  }

  @dangerous_erlang_functions %{
    [:os] => [:cmd],
    [:httpc] => [:request],
    [:gen_tcp] => [:connect],
    [:ssl] => [:connect],
    [:erlang] => [:binary_to_term, :binary_to_atom, :list_to_atom]
  }

  @doc """
  Walk an AST tree, applying pattern matchers at each node.

  Returns a list of findings for the given file.
  """
  @spec walk(Macro.t(), [matcher()], String.t(), atom()) :: [Finding.t()]
  def walk(ast, matchers, file_path, dep_name) do
    initial_state = %{
      file_path: file_path,
      context_stack: [],
      aliases: %{},
      imports: [],
      bindings: %{},
      findings: [],
      matchers: matchers,
      dep_name: dep_name
    }

    {_ast, final_state} = Macro.traverse(ast, initial_state, &pre/2, &post/2)

    Enum.reverse(final_state.findings)
  end

  # --- pre callback ---

  defp pre({:alias, _meta, args} = node, state) when is_list(args) do
    state = track_alias(args, state)
    {node, run_matchers(node, state)}
  end

  # Import tracking: Elixir modules (import System, import System, only: [...])
  defp pre({:import, _meta, [{:__aliases__, _, segments} | _opts]} = node, state) do
    state = %{state | imports: [segments | state.imports]}
    {node, run_matchers(node, state)}
  end

  # Import tracking: Erlang modules (import :os)
  defp pre({:import, _meta, [mod | _opts]} = node, state) when is_atom(mod) do
    state = %{state | imports: [[mod] | state.imports]}
    {node, run_matchers(node, state)}
  end

  # Variable binding: mod = System (Elixir module)
  defp pre({:=, _meta, [{var_name, _, nil}, {:__aliases__, _, segments}]} = node, state)
       when is_atom(var_name) do
    state = %{state | bindings: Map.put(state.bindings, var_name, segments)}
    {node, run_matchers(node, state)}
  end

  # Variable binding: mod = :os (Erlang module)
  defp pre({:=, _meta, [{var_name, _, nil}, mod]} = node, state)
       when is_atom(var_name) and is_atom(mod) and mod != nil and mod != true and mod != false do
    state = %{state | bindings: Map.put(state.bindings, var_name, [mod])}
    {node, run_matchers(node, state)}
  end

  defp pre({:@, _meta, [{attr_name, _, [_expr]}]} = node, state) when is_atom(attr_name) do
    state = push_context(state, :module_attribute)
    {node, run_matchers(node, state)}
  end

  defp pre({:quote, _meta, _args} = node, state) do
    state = push_context(state, :quote)
    {node, run_matchers(node, state)}
  end

  defp pre({form, _meta, _args} = node, state) when is_map_key(@context_openers, form) do
    context = Map.fetch!(@context_openers, form)
    state = push_context(state, context)
    {node, run_matchers(node, state)}
  end

  defp pre(node, state) do
    {node, run_matchers(node, state)}
  end

  # --- post callback ---

  defp post({:@, _meta, [{attr_name, _, [_expr]}]} = node, state) when is_atom(attr_name) do
    {node, pop_context(state, :module_attribute)}
  end

  defp post({:quote, _meta, _args} = node, state) do
    {node, pop_context(state, :quote)}
  end

  defp post({form, _meta, _args} = node, state) when is_map_key(@context_openers, form) do
    expected = Map.fetch!(@context_openers, form)
    {node, pop_context(state, expected)}
  end

  defp post(node, state), do: {node, state}

  # --- matchers ---

  defp run_matchers(node, state) do
    Enum.reduce(state.matchers, state, fn matcher, acc ->
      case matcher.(node, acc) do
        %Finding{} = finding -> %{acc | findings: [finding | acc.findings]}
        nil -> acc
      end
    end)
  end

  # --- alias tracking ---

  defp track_alias([{:__aliases__, _, segments}], state) do
    short = List.last(segments)
    put_in(state, [:aliases, short], segments)
  end

  defp track_alias([{:__aliases__, _, segments}, [as: {:__aliases__, _, [short]}]], state) do
    put_in(state, [:aliases, short], segments)
  end

  defp track_alias(_args, state), do: state

  # --- context helpers ---

  defp push_context(state, context) do
    %{state | context_stack: [context | state.context_stack]}
  end

  defp pop_context(state, expected) do
    case state.context_stack do
      [^expected | rest] -> %{state | context_stack: rest}
      _other -> state
    end
  end

  # --- public helpers for matchers ---

  @doc """
  Resolve a potentially aliased module to its full segments.
  """
  @spec resolve_alias(atom(), walker_state()) :: [atom()]
  def resolve_alias(short, %{aliases: aliases}) do
    Map.get(aliases, short, [short])
  end

  @doc """
  Extract the line number from an AST node's metadata.
  """
  @spec line_from_meta(Macro.t()) :: pos_integer() | nil
  def line_from_meta({_form, meta, _args}) when is_list(meta) do
    Keyword.get(meta, :line)
  end

  def line_from_meta(_node), do: nil

  @doc """
  Extract the column number from an AST node's metadata.
  """
  @spec column_from_meta(Macro.t()) :: pos_integer() | nil
  def column_from_meta({_form, meta, _args}) when is_list(meta) do
    Keyword.get(meta, :column)
  end

  def column_from_meta(_node), do: nil

  @doc """
  Check whether a node is a remote function call matching `module.function`.

  Handles both Elixir-style `Module.func(args)` and Erlang-style `:mod.func(args)`.
  Also handles variable-dispatched calls where the variable is bound to a module.
  Returns `{module_segments, function_atom, args}` or `:nomatch`.
  """
  @spec match_remote_call(Macro.t(), walker_state()) ::
          {[atom()], atom(), [Macro.t()]} | :nomatch
  def match_remote_call(
        {{:., _dot_meta, [{:__aliases__, _, segments}, func]}, _call_meta, args},
        state
      )
      when is_atom(func) and is_list(args) do
    resolved =
      case segments do
        [head | tail] -> resolve_alias(head, state) ++ tail
        [] -> []
      end

    {resolved, func, args}
  end

  def match_remote_call(
        {{:., _dot_meta, [erlang_mod, func]}, _call_meta, args},
        _state
      )
      when is_atom(erlang_mod) and is_atom(func) and is_list(args) do
    {[erlang_mod], func, args}
  end

  # Variable dispatch: var.func(args) where var is bound to a module
  def match_remote_call(
        {{:., _dot_meta, [{var_name, _, nil}, func]}, _call_meta, args},
        state
      )
      when is_atom(var_name) and is_atom(func) and is_list(args) do
    case Map.get(state.bindings, var_name) do
      nil -> :nomatch
      segments -> {segments, func, args}
    end
  end

  def match_remote_call(_node, _state), do: :nomatch

  @doc """
  Resolve any function call node to its module, function, and args.

  Returns:
    - `{:remote, module_segments, function, args, meta}` for Module.func() calls
      (including aliased and variable-dispatched)
    - `{:imported, module_segments, function, args, meta}` for bare function calls
      that match an imported module
    - `:nomatch` for everything else
  """
  @spec resolve_call(Macro.t(), walker_state()) ::
          {:remote, [atom()], atom(), [Macro.t()], keyword()}
          | {:imported, [atom()], atom(), [Macro.t()], keyword()}
          | :nomatch

  # Case 1: Elixir remote call — Module.func(args), resolves aliases
  def resolve_call(
        {{:., _dot_meta, [{:__aliases__, _, segments}, func]}, call_meta, args} = _node,
        state
      )
      when is_atom(func) and is_list(args) do
    resolved =
      case segments do
        [head | tail] -> resolve_alias(head, state) ++ tail
        [] -> []
      end

    {:remote, resolved, func, args, call_meta}
  end

  # Case 2: Erlang remote call — :mod.func(args)
  def resolve_call(
        {{:., _dot_meta, [erlang_mod, func]}, call_meta, args} = _node,
        _state
      )
      when is_atom(erlang_mod) and is_atom(func) and is_list(args) do
    {:remote, [erlang_mod], func, args, call_meta}
  end

  # Case 3: Variable dispatch — var.func(args) where var is bound
  def resolve_call(
        {{:., _dot_meta, [{var_name, _, nil}, func]}, call_meta, args} = _node,
        state
      )
      when is_atom(var_name) and is_atom(func) and is_list(args) do
    case Map.get(state.bindings, var_name) do
      nil -> :nomatch
      segments -> {:remote, segments, func, args, call_meta}
    end
  end

  # Case 4: Bare function call — func(args), check imports
  @special_forms [
    :def, :defp, :defmacro, :defmacrop, :defmodule, :alias, :import, :require, :use,
    :quote, :if, :unless, :case, :cond, :with, :for, :fn, :receive, :try, :raise, :throw,
    :super, :__block__, :__aliases__, :@, :&, :|>, :=, :., :<<>>, :%{}, :{}, :%, :^,
    :in, :when, :do, :else, :end
  ]

  def resolve_call({func, call_meta, args} = _node, state)
      when is_atom(func) and is_list(args) and func not in @special_forms do
    case find_imported_module(func, length(args), state) do
      nil -> :nomatch
      module_segments -> {:imported, module_segments, func, args, call_meta}
    end
  end

  def resolve_call(_node, _state), do: :nomatch

  # --- import resolution helpers ---

  defp find_imported_module(func, arity, state) do
    Enum.find_value(state.imports, fn module_segments ->
      module_atom = module_to_atom(module_segments)

      cond do
        # Try runtime introspection first
        module_atom != nil and Code.ensure_loaded?(module_atom) and
            function_exported?(module_atom, func, arity) ->
          module_segments

        # Fall back to static dangerous functions table
        func in Map.get(@dangerous_functions, module_segments, []) ->
          module_segments

        func in Map.get(@dangerous_erlang_functions, module_segments, []) ->
          module_segments

        true ->
          nil
      end
    end)
  end

  defp module_to_atom(segments) when is_list(segments) do
    try do
      Module.concat(segments)
    rescue
      _ -> nil
    end
  end
end
