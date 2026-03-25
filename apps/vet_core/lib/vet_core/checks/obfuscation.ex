defmodule VetCore.Checks.Obfuscation do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :obfuscation
  @base_severity :warning

  @entropy_threshold 5.5
  @min_string_length 40

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      findings_decode_eval = scan_decode_eval(ast, dep_name, file_path, source)

      findings_entropy_and_apply =
        Walker.walk(
          ast,
          [
            &match_high_entropy(&1, &2, dep_name, source),
            &match_dynamic_apply(&1, &2, dep_name, source)
          ],
          file_path,
          dep_name
        )

      findings_decode_eval ++ findings_entropy_and_apply
    end)
  end

  # ---------- Pattern 1: Base.decode64 near Code.eval_string ----------
  # This pattern checks co-occurrence within a scope, so it uses its own
  # AST traversal with resolve_call for the inner has_call? checks.

  defp scan_decode_eval(ast, dep_name, file_path, source) do
    find_decode_eval_pairs(ast)
    |> Enum.map(fn {line, column} ->
      %Finding{
        dep_name: dep_name,
        file_path: file_path,
        line: line,
        column: column,
        check_id: :obfuscation_decode_eval,
        category: @category,
        severity: :critical,
        compile_time?: true,
        snippet: FileHelper.snippet(source, line),
        description:
          "Base.decode64 and Code.eval_string found in the same scope — " <>
            "likely obfuscated code execution"
      }
    end)
  end

  defp find_decode_eval_pairs(ast) do
    bodies = extract_bodies(ast)

    Enum.flat_map(bodies, fn {body_ast, line, column} ->
      has_decode = has_call?(body_ast, [:Base], :decode64)
      has_eval = has_call?(body_ast, [:Code], :eval_string)

      if has_decode and has_eval do
        [{line, column}]
      else
        []
      end
    end)
  end

  defp extract_bodies(ast) do
    {_, bodies} =
      Macro.prewalk(ast, [], fn
        {form, meta, [_name_args, [do: body]]} = node, acc
        when form in [:def, :defp, :defmacro, :defmacrop] ->
          {node, [{body, meta[:line] || 0, meta[:column]} | acc]}

        {:defmodule, meta, [_alias, [do: body]]} = node, acc ->
          {node, [{body, meta[:line] || 0, meta[:column]} | acc]}

        node, acc ->
          {node, acc}
      end)

    bodies
  end

  defp has_call?(ast, module_parts, func) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        {{:., _, [{:__aliases__, _, ^module_parts}, ^func]}, _, _} = node, _acc ->
          {node, true}

        node, acc ->
          {node, acc}
      end)

    found
  end

  # ---------- Pattern 2: High-entropy string literals ----------
  # Operates on raw string literal nodes, not remote calls — stays as direct AST matching.

  defp match_high_entropy(node, state, dep_name, source) do
    case node do
      str when is_binary(str) and byte_size(str) > @min_string_length ->
        entropy = shannon_entropy(str)

        if entropy > @entropy_threshold and not natural_language?(str) and
             not base64_data_uri?(str) do
          line = find_string_line(source, str)
          is_ct = FileHelper.compile_time?(state.context_stack)

          %Finding{
            dep_name: dep_name,
            file_path: state.file_path,
            line: line,
            column: nil,
            check_id: :obfuscation_entropy,
            category: @category,
            severity: :critical,
            compile_time?: is_ct,
            snippet: FileHelper.snippet(source, line),
            description:
              "High-entropy string literal (Shannon entropy: #{Float.round(entropy, 2)}) — " <>
                "possible obfuscated payload"
          }
        else
          nil
        end

      _ ->
        nil
    end
  end

  # ---------- Pattern 3: Dynamic apply/3 ----------
  # Uses resolve_call for Kernel.apply, and direct AST matching for bare apply/3.

  defp match_dynamic_apply(node, state, dep_name, source) do
    case match_apply_pattern(node, state) do
      nil ->
        nil

      {description, line, column} ->
        is_ct = FileHelper.compile_time?(state.context_stack)

        %Finding{
          dep_name: dep_name,
          file_path: state.file_path,
          line: line,
          column: column,
          check_id: :obfuscation_dynamic_apply,
          category: @category,
          severity: @base_severity,
          compile_time?: is_ct,
          snippet: FileHelper.snippet(source, line),
          description: description
        }
    end
  end

  # Bare apply/3 with non-literal module or function
  defp match_apply_pattern({:apply, meta, [mod, func, _args]}, _state)
       when not is_atom(mod) or not is_atom(func) do
    case {mod, func} do
      {m, f} when is_atom(m) and is_atom(f) ->
        nil

      _ ->
        {"Dynamic apply/3 call with non-literal module or function — " <>
           "may be used to obscure the actual function being called",
         meta[:line] || 0, meta[:column]}
    end
  end

  # Kernel.apply/3 via resolve_call
  defp match_apply_pattern(node, state) do
    with {_type, [:Kernel], :apply, [mod, func, _args], meta} <-
           Walker.resolve_call(node, state),
         false <- is_atom(mod) and is_atom(func) do
      {"Dynamic Kernel.apply/3 call with non-literal module or function — " <>
         "may be used to obscure the actual function being called",
       meta[:line] || 0, meta[:column]}
    else
      _ -> nil
    end
  end

  # ---------- Helpers ----------

  defp shannon_entropy(string) do
    bytes = :binary.bin_to_list(string)
    len = length(bytes)

    bytes
    |> Enum.frequencies()
    |> Map.values()
    |> Enum.reduce(0.0, fn count, entropy ->
      p = count / len
      entropy - p * :math.log2(p)
    end)
  end

  defp base64_data_uri?(str) do
    String.starts_with?(str, "data:image/") or String.starts_with?(str, "data:application/")
  end

  defp natural_language?(str) do
    space_ratio = (str |> String.graphemes() |> Enum.count(&(&1 == " "))) / String.length(str)
    space_ratio > 0.10
  end

  defp find_string_line(source, str) do
    needle = String.slice(str, 0, 40)

    source
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.find_value(1, fn {line_text, idx} ->
      if String.contains?(line_text, needle), do: idx
    end)
  end
end
