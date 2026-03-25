defmodule VetCore.LockParser do
  @moduledoc false

  alias VetCore.Types.Dependency

  def parse(project_path) do
    lock_path = Path.join(project_path, "mix.lock")

    case File.read(lock_path) do
      {:ok, contents} ->
        {lock_map, _bindings} =
          if function_exported?(Code, :with_diagnostics, 1) do
            {result, _diagnostics} = Code.with_diagnostics(fn -> Code.eval_string(contents) end)
            result
          else
            Code.eval_string(contents)
          end
        deps = Enum.map(lock_map, fn {name, entry} -> parse_entry(name, entry) end)
        {:ok, deps}

      {:error, reason} ->
        {:error, "Failed to parse mix.lock: #{inspect(reason)}"}
    end
  end

  defp parse_entry(name, {:hex, _pkg, version, _outer_hash, _managers, _deps, _repo, inner_hash}) do
    %Dependency{
      name: name,
      version: version,
      hash: inner_hash,
      source: :hex
    }
  end

  defp parse_entry(name, {:hex, _pkg, version, outer_hash, _managers, _deps, _repo}) do
    %Dependency{
      name: name,
      version: version,
      hash: outer_hash,
      source: :hex
    }
  end

  defp parse_entry(name, {:git, url, commit, _opts}) do
    %Dependency{
      name: name,
      version: commit,
      hash: commit,
      source: {:git, url}
    }
  end

  defp parse_entry(name, _unknown) do
    %Dependency{
      name: name,
      source: :hex
    }
  end
end
