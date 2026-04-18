defmodule VetCore.Checks.FileAccess do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :file_access
  @base_severity :warning

  @sensitive_paths ~w(~/.ssh ~/.aws ~/.kube ~/.gnupg ~/.config /etc/passwd /etc/shadow)

  # Elixir File.* functions that access the filesystem.
  # `:open` and `:open!` added for GH issue #5.
  @file_functions [
    :read!,
    :write!,
    :stream!,
    :rm,
    :rm_rf,
    :read,
    :write,
    :cp,
    :cp_r,
    :open,
    :open!
  ]

  # Erlang :file module functions that access the filesystem.
  # GH issue #6 — these were not checked at all.
  @erlang_file_functions [
    :read_file,
    :read_file_info,
    :consult,
    :open,
    :read,
    :pread,
    :script,
    :path_consult,
    :path_script,
    :list_dir,
    :read_link,
    :write_file,
    :delete,
    :del_dir,
    :rename,
    :make_link,
    :make_symlink
  ]

  @doc """
  Returns every `{module_segments, function_atom}` pattern this check detects,
  for both Elixir's `File` and Erlang's `:file` modules.

  Exposed so the coverage sweep test in
  `apps/vet_core/test/vet_core/checks/coverage_test.exs` can assert that
  the declared target list and the swept calls are exactly equal.
  """
  def target_patterns do
    elixir = for f <- @file_functions, do: {[:File], f}
    erlang = for f <- @erlang_file_functions, do: {[:file], f}
    elixir ++ erlang
  end

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_name
    |> FileHelper.read_and_parse(project_path)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    case Walker.resolve_call(node, state) do
      {_type, [:File], func, args, meta} ->
        if func in @file_functions do
          build_finding("File", func, args, meta, state, dep_name, source)
        end

      {_type, [:file], func, args, meta} ->
        if func in @erlang_file_functions do
          build_finding(":file", func, args, meta, state, dep_name, source)
        end

      _ ->
        nil
    end
  end

  defp build_finding(module_label, func, args, meta, state, dep_name, source) do
    sensitive? = args_contain_sensitive_path?(args)
    is_ct = FileHelper.compile_time?(state.context_stack)

    # Severity tiers:
    #
    #   - sensitive path (~/.ssh, /etc/passwd, ...)  → :critical
    #     The path itself is hostile regardless of CT/RT.
    #
    #   - compile-time + non-sensitive → :info
    #     CT execution runs on the *developer's* machine. There is no user-
    #     input vector at CT, so the path is bounded by what the developer
    #     wrote (literal or variable bound to literal in the same module).
    #     The two CT exfil channels — network calls and binary_to_term/eval
    #     of the file content — are caught independently by the Network and
    #     CodeEval checks. Surface the surface area so users can audit, but
    #     don't drive scoring with it. This is the standard Phoenix /
    #     phoenix_live_dashboard / phoenix_html bundling pattern.
    #
    #   - runtime + non-sensitive → :warning
    #     Path could come from user input. Default suspicion.
    severity =
      cond do
        sensitive? -> :critical
        is_ct -> :info
        true -> @base_severity
      end

    line = meta[:line] || 0

    desc =
      cond do
        sensitive? ->
          "Call to #{module_label}.#{func} accessing a sensitive path — potential credential exfiltration"

        is_ct ->
          "Call to #{module_label}.#{func} at compile time — bundled asset/template/version read"

        true ->
          "Call to #{module_label}.#{func} — filesystem access"
      end

    %Finding{
      dep_name: dep_name,
      file_path: state.file_path,
      line: line,
      column: meta[:column],
      check_id: :file_access,
      category: @category,
      severity: severity,
      compile_time?: is_ct,
      snippet: FileHelper.snippet(source, line),
      description: desc
    }
  end

  defp args_contain_sensitive_path?(args) do
    Enum.any?(args, &arg_contains_sensitive?/1)
  rescue
    _ -> false
  end

  # Recursive check — peek inside Path.expand / Path.join / interpolations
  # so wrapping a sensitive literal in a path helper doesn't evade detection.
  defp arg_contains_sensitive?(arg) when is_binary(arg) do
    Enum.any?(@sensitive_paths, &String.contains?(arg, &1))
  end

  defp arg_contains_sensitive?(arg) when is_list(arg) do
    case List.to_string(arg) do
      bin when is_binary(bin) ->
        Enum.any?(@sensitive_paths, &String.contains?(bin, &1))
    end
  rescue
    # Not a charlist (mixed list of ASTs) — recurse into each element.
    _ -> Enum.any?(arg, &arg_contains_sensitive?/1)
  end

  defp arg_contains_sensitive?({:<<>>, _, parts}) do
    parts
    |> Enum.filter(&is_binary/1)
    |> Enum.any?(fn part ->
      Enum.any?(@sensitive_paths, &String.contains?(part, &1))
    end)
  end

  defp arg_contains_sensitive?({:sigil_c, _, [{:<<>>, _, [path]}, _]}) when is_binary(path) do
    Enum.any?(@sensitive_paths, &String.contains?(path, &1))
  end

  # Path helpers — Path.expand("~/.ssh/id_rsa"), Path.join([...]), Path.absname(...)
  defp arg_contains_sensitive?(
         {{:., _, [{:__aliases__, _, [:Path]}, fn_name]}, _, fn_args}
       )
       when fn_name in [:expand, :join, :absname, :rootname, :extname] do
    Enum.any?(fn_args, &arg_contains_sensitive?/1)
  end

  # Erlang :filename — :filename.join, :filename.absname etc.
  defp arg_contains_sensitive?({{:., _, [:filename, _fn_name]}, _, fn_args}) do
    Enum.any?(fn_args, &arg_contains_sensitive?/1)
  end

  defp arg_contains_sensitive?(_), do: false
end
