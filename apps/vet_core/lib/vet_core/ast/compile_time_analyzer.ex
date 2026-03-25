defmodule VetCore.AST.CompileTimeAnalyzer do
  @moduledoc false

  alias VetCore.Types.Finding

  @doc """
  Classify a finding as compile-time or runtime based on the context stack
  that was active when the finding was produced, then escalate severity
  when appropriate.

  Returns an updated `%Finding{}` with `compile_time?` and `severity` set.
  """
  @spec classify(Finding.t(), [VetCore.AST.Walker.context()], String.t()) :: Finding.t()
  def classify(%Finding{} = finding, context_stack, file_path) do
    compile_time? = compile_time?(context_stack, file_path)

    finding
    |> Map.put(:compile_time?, compile_time?)
    |> maybe_escalate()
  end

  @doc """
  Classify a list of findings produced by `VetCore.AST.Walker.walk/4`.

  Each finding is classified against the provided context stack and file path.
  """
  @spec classify_all([Finding.t()], [VetCore.AST.Walker.context()], String.t()) :: [Finding.t()]
  def classify_all(findings, context_stack, file_path) do
    Enum.map(findings, &classify(&1, context_stack, file_path))
  end

  @doc """
  Determine whether the given context stack represents a compile-time
  execution context.

  Classification rules (evaluated top-to-bottom, first match wins):

  | Context stack                                       | Result       |
  |-----------------------------------------------------|--------------|
  | Inside `def`/`defp` with no enclosing `defmacro`    | runtime      |
  | Inside `defmacro`/`defmacrop`                       | compile-time |
  | Inside module attribute (`@attr value`)              | compile-time |
  | In module body (inside `defmodule`, outside any def) | compile-time |
  | Inside `quote` block within a macro                  | compile-time |
  | File ends in `mix.exs`                               | compile-time |
  | Default                                              | runtime      |
  """
  @spec compile_time?([VetCore.AST.Walker.context()], String.t()) :: boolean()
  def compile_time?(context_stack, file_path) do
    cond do
      String.ends_with?(file_path, "mix.exs") ->
        true

      :module_attribute in context_stack ->
        true

      :defmacro in context_stack ->
        true

      :quote in context_stack and :defmacro in context_stack ->
        true

      in_def_without_macro?(context_stack) ->
        false

      in_module_body?(context_stack) ->
        true

      true ->
        false
    end
  end

  # Inside def/defp with no enclosing defmacro
  defp in_def_without_macro?(context_stack) do
    :def in context_stack and :defmacro not in context_stack
  end

  # Inside defmodule but outside any def or defmacro
  defp in_module_body?(context_stack) do
    :module_body in context_stack and
      :def not in context_stack and
      :defmacro not in context_stack
  end

  # Escalate :warning → :critical for compile-time findings
  defp maybe_escalate(%Finding{compile_time?: true, severity: :warning} = finding) do
    %{finding | severity: :critical}
  end

  defp maybe_escalate(finding), do: finding
end
