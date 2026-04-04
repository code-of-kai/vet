defmodule VetCore.LockParser do
  @moduledoc """
  Parses mix.lock without executing its contents.

  Uses Code.string_to_quoted (AST only) instead of Code.eval_string
  to prevent arbitrary code execution from a crafted lock file.
  """

  alias VetCore.Types.Dependency

  def parse(project_path) do
    lock_path = Path.join(project_path, "mix.lock")

    case File.read(lock_path) do
      {:ok, contents} ->
        case Code.string_to_quoted(contents) do
          {:ok, {:%{}, _meta, entries}} when is_list(entries) ->
            deps = Enum.flat_map(entries, &parse_entry/1)
            {:ok, deps}

          {:ok, _other} ->
            {:error, "mix.lock does not contain a map literal"}

          {:error, reason} ->
            {:error, "Failed to parse mix.lock: #{inspect(reason)}"}
        end

      {:error, reason} ->
        {:error, "Failed to read mix.lock: #{inspect(reason)}"}
    end
  end

  # Keyword entry: {name_atom, tuple_ast}
  defp parse_entry({name, {:{}, _meta, [:hex, _pkg, version, _hash1, _managers, _deps, repo, hash2]}})
       when is_atom(name) do
    [%Dependency{name: name, version: version, hash: hash2, source: :hex}]
  end

  defp parse_entry({name, {:{}, _meta, [:hex, _pkg, version, hash, _managers, _deps, _repo]}})
       when is_atom(name) do
    [%Dependency{name: name, version: version, hash: hash, source: :hex}]
  end

  defp parse_entry({name, {:{}, _meta, [:git, url, commit, _opts]}})
       when is_atom(name) do
    [%Dependency{name: name, version: commit, hash: commit, source: {:git, url}}]
  end

  defp parse_entry({name, _unknown}) when is_atom(name) do
    [%Dependency{name: name, source: :hex}]
  end

  defp parse_entry(_), do: []
end
