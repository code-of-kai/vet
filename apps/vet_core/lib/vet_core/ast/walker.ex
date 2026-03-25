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

  def match_remote_call(_node, _state), do: :nomatch
end
