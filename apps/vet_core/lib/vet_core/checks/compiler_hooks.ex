defmodule VetCore.Checks.CompilerHooks do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @impl true
  def init(opts), do: opts

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(
        ast,
        [
          &match_module_attributes(&1, &2, dep_name, source),
          &match_compilers_call(&1, &2, dep_name, source),
          &match_custom_compilers(&1, &2, dep_name, source)
        ],
        file_path,
        dep_name
      )
    end)
  end

  # Detect @before_compile, @after_compile, @external_resource via direct AST pattern
  # These are module attributes, not remote calls, so they stay as direct AST matching.
  defp match_module_attributes(node, state, dep_name, source) do
    case node do
      {:@, meta, [{:before_compile, _, _}]} ->
        build_finding(
          "@before_compile callback — code runs at compile time, can execute arbitrary logic",
          :critical,
          meta,
          state,
          dep_name,
          source
        )

      {:@, meta, [{:after_compile, _, _}]} ->
        build_finding(
          "@after_compile callback — code runs after compilation, can execute arbitrary logic",
          :critical,
          meta,
          state,
          dep_name,
          source
        )

      {:@, meta, [{:external_resource, _, _}]} ->
        build_finding(
          "@external_resource — triggers recompilation based on external file, runs at compile time",
          :warning,
          meta,
          state,
          dep_name,
          source
        )

      _ ->
        nil
    end
  end

  # Detect Mix.compilers() via resolve_call
  defp match_compilers_call(node, state, dep_name, source) do
    with {_type, [:Mix], :compilers, _args, meta} <- Walker.resolve_call(node, state) do
      build_finding(
        "Mix.compilers() usage — may customize the compilation pipeline",
        :critical,
        meta,
        state,
        dep_name,
        source
      )
    else
      _ -> nil
    end
  end

  # Detect custom compilers in mix.exs: `compilers: [...]`
  # This is a bare function call / keyword, not a remote call, so direct AST matching.
  defp match_custom_compilers(node, state, dep_name, source) do
    case node do
      {:compilers, meta, [[_ | _] = _compilers]} ->
        build_finding(
          "Custom compilers defined in mix.exs — may execute arbitrary code during compilation",
          :critical,
          meta,
          state,
          dep_name,
          source
        )

      _ ->
        nil
    end
  end

  defp build_finding(description, severity, meta, state, dep_name, source) do
    is_ct = FileHelper.compile_time?(state.context_stack)
    line = meta[:line] || 0

    %Finding{
      dep_name: dep_name,
      file_path: state.file_path,
      line: line,
      column: meta[:column],
      check_id: :compiler_hooks,
      category: :compiler_hooks,
      severity: severity,
      compile_time?: is_ct,
      snippet: FileHelper.snippet(source, line),
      description: description
    }
  end
end
