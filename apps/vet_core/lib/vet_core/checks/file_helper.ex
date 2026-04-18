defmodule VetCore.Checks.FileHelper do
  @moduledoc false

  require Logger

  @doc """
  Finds all .ex and .exs files in a dependency's directory, reads each file,
  parses it to AST, and returns a list of `{file_path, source, ast}` tuples.

  Files that fail to parse are skipped with a warning.
  """
  @spec read_and_parse(dep_name :: atom(), project_path :: String.t()) ::
          [{String.t(), String.t(), Macro.t()}]
  def read_and_parse(dep_name, project_path) do
    dep_name
    |> discover_files(project_path)
    |> parse_files_parallel()
  end

  @doc """
  Returns parsed files for a dependency, preferring a cached list from the
  check `state` keyword list. This is the clearwing-style read-once-per-dep
  optimization: the scanner parses once, all checks share the result instead
  of each check re-parsing every file in the dep.

  Falls back to `read_and_parse/2` when no cache is present (backward compat
  for direct callers or tests that instantiate checks without a scanner).
  """
  @spec parsed_files(dep_name :: atom(), project_path :: String.t(), state :: keyword()) ::
          [{String.t(), String.t(), Macro.t()}]
  def parsed_files(dep_name, project_path, state) when is_list(state) do
    case Keyword.get(state, :parsed_files) do
      nil -> read_and_parse(dep_name, project_path)
      cached when is_list(cached) -> cached
    end
  end

  def parsed_files(dep_name, project_path, _state),
    do: read_and_parse(dep_name, project_path)

  defp discover_files(dep_name, project_path) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    [
      Path.join([dep_dir, "lib", "**", "*.ex"]),
      Path.join([dep_dir, "lib", "**", "*.exs"]),
      Path.join([dep_dir, "mix.exs"])
    ]
    |> Enum.flat_map(&Path.wildcard/1)
    |> Enum.uniq()
  end

  defp parse_files_parallel([]), do: []

  defp parse_files_parallel(paths) do
    # Parallel file I/O + parse. Bounded concurrency so a dep with thousands of
    # files doesn't saturate the scheduler. Timeout is generous for large files.
    paths
    |> Task.async_stream(&parse_one/1,
      max_concurrency: System.schedulers_online() * 2,
      timeout: 30_000,
      on_timeout: :kill_task,
      ordered: false
    )
    |> Enum.flat_map(fn
      {:ok, {:ok, triple}} -> [triple]
      {:ok, :skip} -> []
      {:exit, _reason} -> []
    end)
  end

  defp parse_one(file_path) do
    with {:ok, source} <- File.read(file_path),
         {:ok, ast} <- Code.string_to_quoted(source, columns: true, file: file_path) do
      {:ok, {file_path, source, ast}}
    else
      {:error, reason} ->
        Logger.warning("Vet: skipping #{file_path}: #{inspect(reason)}")
        :skip

      _ ->
        Logger.warning("Vet: skipping #{file_path}: parse error")
        :skip
    end
  rescue
    e ->
      Logger.warning("Vet: skipping #{file_path}: #{Exception.message(e)}")
      :skip
  end

  @doc """
  Extracts a snippet from source text around the given line number.
  """
  @spec snippet(String.t(), pos_integer(), non_neg_integer()) :: String.t()
  def snippet(source, line, context_lines \\ 0) do
    lines = String.split(source, "\n")

    start = max(line - context_lines - 1, 0)
    stop = min(line + context_lines, length(lines))

    lines
    |> Enum.slice(start, stop - start)
    |> Enum.join("\n")
    |> String.trim()
  end

  @doc """
  Determines whether a match is compile-time based on its context stack.

  The context stack is a list of atoms built during AST traversal:
  - `:def` or `:defp` — inside a function definition (runtime)
  - `:defmacro` or `:defmacrop` — inside a macro definition (compile-time)
  - `:module_body` — at the top level of a defmodule (compile-time)

  Returns `true` if the code runs at compile time.
  """
  @spec compile_time?(list(atom())) :: boolean()
  def compile_time?(context_stack) do
    cond do
      :defmacro in context_stack or :defmacrop in context_stack -> true
      :def in context_stack or :defp in context_stack -> false
      true -> true
    end
  end

end
