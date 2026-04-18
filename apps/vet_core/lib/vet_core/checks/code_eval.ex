defmodule VetCore.Checks.CodeEval do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :code_eval
  @base_severity :critical

  @patterns [
    {[:Code], :eval_string},
    {[:Code], :eval_quoted},
    {[:Code], :eval_file},
    {[:Code], :compile_string},
    {[:Code], :compile_quoted},
    {[:erlang], :binary_to_term},
    {[:Module], :create},
    # Erlang :compile module — dynamic compilation of Erlang source or forms.
    # GH issue #4.
    {[:compile], :file},
    {[:compile], :forms},
    {[:compile], :file_binary},
    {[:compile], :noenv_file},
    {[:compile], :noenv_forms}
  ]

  @pattern_set MapSet.new(@patterns)

  @doc """
  Returns every `{module_segments, function_atom}` pattern this check detects.

  Exposed so the coverage sweep test in
  `apps/vet_core/test/vet_core/checks/coverage_test.exs` can assert that
  the declared target list and the swept calls are exactly equal. Adding
  a new pattern here without also adding a matching call to the sweep
  fails the test loudly.
  """
  def target_patterns, do: @patterns

  @descriptions %{
    {[:Code], :eval_string} =>
      "Call to Code.eval_string — dynamically evaluates Elixir code from a string",
    {[:Code], :eval_quoted} =>
      "Call to Code.eval_quoted — dynamically evaluates quoted Elixir expressions",
    {[:Code], :eval_file} =>
      "Call to Code.eval_file — evaluates an entire file as Elixir code",
    {[:Code], :compile_string} =>
      "Call to Code.compile_string — compiles Elixir code from a string at runtime",
    {[:Code], :compile_quoted} =>
      "Call to Code.compile_quoted — compiles quoted Elixir expressions at runtime",
    {[:erlang], :binary_to_term} =>
      "Call to :erlang.binary_to_term — deserializes Erlang terms, potential code execution vector",
    {[:Module], :create} =>
      "Call to Module.create/3 — dynamically creates a module at runtime",
    {[:compile], :file} =>
      "Call to :compile.file — compiles an Erlang source file at runtime",
    {[:compile], :forms} =>
      "Call to :compile.forms — compiles Erlang AST forms at runtime",
    {[:compile], :file_binary} =>
      "Call to :compile.file_binary — compiles Erlang source and returns a BEAM binary",
    {[:compile], :noenv_file} =>
      "Call to :compile.noenv_file — compiles an Erlang file without the standard environment",
    {[:compile], :noenv_forms} =>
      "Call to :compile.noenv_forms — compiles Erlang forms without the standard environment"
  }

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, state) do
    dep_name
    |> FileHelper.parsed_files(project_path, state)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    with {_type, module, func, _args, meta} <- Walker.resolve_call(node, state),
         true <- Walker.matches_pattern?(module, func, @pattern_set) do
      is_ct = FileHelper.compile_time?(state.context_stack)
      severity = if is_ct, do: :critical, else: @base_severity
      line = meta[:line] || 0

      description =
        Map.get(@descriptions, {module, func}, "Call to #{format_call(module, func)}")

      %Finding{
        dep_name: dep_name,
        file_path: state.file_path,
        line: line,
        column: meta[:column],
        check_id: :code_eval,
        category: @category,
        severity: severity,
        compile_time?: is_ct,
        snippet: FileHelper.snippet(source, line),
        description: description
      }
    else
      _ -> nil
    end
  end

  defp format_call([mod], func), do: "#{mod}.#{func}"
  defp format_call(mods, func), do: "#{Enum.join(mods, ".")}.#{func}"
end
