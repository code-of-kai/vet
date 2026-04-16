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

    severity =
      cond do
        sensitive? -> :critical
        is_ct -> :critical
        true -> @base_severity
      end

    line = meta[:line] || 0

    desc =
      if sensitive? do
        "Call to #{module_label}.#{func} accessing a sensitive path — potential credential exfiltration"
      else
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
    Enum.any?(args, fn
      arg when is_binary(arg) ->
        Enum.any?(@sensitive_paths, &String.contains?(arg, &1))

      arg when is_list(arg) ->
        # Erlang charlist: `~c"/etc/passwd"` parses to a list of integers.
        case List.to_string(arg) do
          bin when is_binary(bin) ->
            Enum.any?(@sensitive_paths, &String.contains?(bin, &1))

          _ ->
            false
        end

      {:<<>>, _, parts} ->
        parts
        |> Enum.filter(&is_binary/1)
        |> Enum.any?(fn part ->
          Enum.any?(@sensitive_paths, &String.contains?(part, &1))
        end)

      {:sigil_c, _, [{:<<>>, _, [path]}, _]} when is_binary(path) ->
        # `~c"/etc/passwd"` sigil literal — string form is preserved.
        Enum.any?(@sensitive_paths, &String.contains?(path, &1))

      _ ->
        false
    end)
  rescue
    _ -> false
  end
end
