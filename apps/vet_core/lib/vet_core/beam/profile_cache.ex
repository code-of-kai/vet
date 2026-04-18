defmodule VetCore.BEAM.ProfileCache do
  @moduledoc """
  Persistent cache of `VetCore.BEAM.BeamProfile` snapshots, keyed by
  `{package_name, version}`.

  The cache lives at `<project>/.vet/beam_profiles/<package>/<version>/`.
  Each module's profile is stored as a binary file produced by
  `:erlang.term_to_binary/1` for fast load and exact round-trip.

  Why this exists: BEAM-level version diffing requires *both* old and new
  compiled artifacts. Once a user installs version 1.0 of a package and
  scans it, we have its profiles; when they upgrade to 1.1 we can compare
  the new profiles against the cached 1.0 snapshot — even though we never
  recompile the old version.

  Snapshots are content-addressed by `BeamProfile.content_hash/1` to make
  storage idempotent: re-snapshotting the same version is a no-op.
  """

  alias VetCore.BEAM.BeamProfile

  @cache_dir ".vet/beam_profiles"
  @manifest "manifest.json"

  @doc """
  Persist a list of `BeamProfile` snapshots for a `{package, version}`.

  Overwrites any prior snapshot for the same version.
  """
  @spec save([BeamProfile.t()], String.t(), atom(), String.t()) :: :ok
  def save(profiles, project_path, package_name, version)
      when is_list(profiles) and is_binary(project_path) and is_atom(package_name) and
             is_binary(version) do
    dir = version_dir(project_path, package_name, version)
    File.mkdir_p!(dir)

    manifest =
      Enum.map(profiles, fn %BeamProfile{} = profile ->
        slug = module_slug(profile.module)
        path = Path.join(dir, slug <> ".profile")
        File.write!(path, :erlang.term_to_binary(profile))

        %{
          "module" => to_string(profile.module),
          "file" => slug <> ".profile",
          "content_hash" => BeamProfile.content_hash(profile)
        }
      end)

    File.write!(Path.join(dir, @manifest), Jason.encode!(manifest, pretty: true))
    :ok
  end

  @doc """
  Load every profile saved for a `{package, version}`. Returns an empty
  list if the version is not in cache.
  """
  @spec load([String.t()] | atom(), String.t(), String.t()) :: [BeamProfile.t()]
  def load(project_path, package_name, version) do
    dir = version_dir(project_path, package_name, version)

    case File.ls(dir) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&String.ends_with?(&1, ".profile"))
        |> Enum.flat_map(fn entry ->
          path = Path.join(dir, entry)

          with {:ok, bin} <- File.read(path),
               %BeamProfile{} = profile <- safe_term(bin) do
            [profile]
          else
            _ -> []
          end
        end)

      {:error, _} ->
        []
    end
  end

  @doc """
  List all cached versions for a package, sorted lexically (callers that
  need semver ordering should re-sort).
  """
  @spec versions(String.t(), atom()) :: [String.t()]
  def versions(project_path, package_name) do
    dir = package_dir(project_path, package_name)

    case File.ls(dir) do
      {:ok, entries} -> Enum.sort(entries)
      {:error, _} -> []
    end
  end

  @doc """
  Remove a single cached version.
  """
  @spec drop(String.t(), atom(), String.t()) :: :ok
  def drop(project_path, package_name, version) do
    dir = version_dir(project_path, package_name, version)
    File.rm_rf!(dir)
    :ok
  end

  # --- Internals -------------------------------------------------------------

  defp package_dir(project_path, package_name) do
    Path.join([project_path, @cache_dir, to_string(package_name)])
  end

  defp version_dir(project_path, package_name, version) do
    Path.join(package_dir(project_path, package_name), version)
  end

  defp module_slug(nil), do: "_unknown"

  defp module_slug(module) when is_atom(module) do
    module
    |> Atom.to_string()
    |> String.replace(~r/[^A-Za-z0-9_.-]/, "_")
  end

  # `:erlang.binary_to_term/2` with `[:safe]` rejects payloads that would
  # create new atoms or function references — fine for profile structs.
  defp safe_term(bin) do
    :erlang.binary_to_term(bin, [:safe])
  rescue
    _ -> nil
  end
end
