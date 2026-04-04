defmodule VetCore.VersionDiff do
  @moduledoc false

  alias VetCore.Types.Finding

  defstruct [
    :package_name,
    :old_version,
    :new_version,
    new_files: [],
    removed_files: [],
    modified_files: [],
    new_findings: [],
    resolved_findings: [],
    profile_shift: nil
  ]

  @type t :: %__MODULE__{
          package_name: atom(),
          old_version: String.t(),
          new_version: String.t(),
          new_files: [String.t()],
          removed_files: [String.t()],
          modified_files: [String.t()],
          new_findings: [Finding.t()],
          resolved_findings: [Finding.t()],
          profile_shift: map() | nil
        }

  def diff(_project_path, package_name, old_version, new_version) do
    old_dir = fetch_version_source(package_name, old_version)
    new_dir = fetch_version_source(package_name, new_version)

    cond do
      old_dir == nil or new_dir == nil ->
        {:error, :version_unavailable}

      true ->
        old_files = list_source_files(old_dir)
        new_files = list_source_files(new_dir)

        old_set = MapSet.new(old_files, &relative_path(&1, old_dir))
        new_set = MapSet.new(new_files, &relative_path(&1, new_dir))

        added = MapSet.difference(new_set, old_set) |> MapSet.to_list()
        removed = MapSet.difference(old_set, new_set) |> MapSet.to_list()

        common = MapSet.intersection(old_set, new_set) |> MapSet.to_list()

        modified =
          Enum.filter(common, fn rel_path ->
            old_hash = hash_file(Path.join(old_dir, rel_path))
            new_hash = hash_file(Path.join(new_dir, rel_path))
            old_hash != new_hash
          end)

        {:ok,
         %__MODULE__{
           package_name: package_name,
           old_version: old_version,
           new_version: new_version,
           new_files: added,
           removed_files: removed,
           modified_files: modified
         }}
    end
  end

  def suspicious_delta?(%__MODULE__{} = diff) do
    signals = []

    signals =
      if length(diff.new_files) > 0 and
           Enum.any?(diff.new_files, &(not String.contains?(&1, "test"))),
         do: [:unexpected_new_files | signals],
         else: signals

    signals =
      if diff.profile_shift != nil,
        do: [:profile_shift | signals],
        else: signals

    signals =
      if length(diff.new_findings) > length(diff.resolved_findings),
        do: [:findings_increased | signals],
        else: signals

    {signals != [], signals}
  end

  @package_name_re ~r/^[a-z][a-z0-9_]{0,63}$/
  @version_re ~r/^[a-zA-Z0-9._\-+]{1,64}$/

  defp fetch_version_source(package_name, version) do
    name_str = to_string(package_name)

    unless Regex.match?(@package_name_re, name_str) and Regex.match?(@version_re, version) do
      raise ArgumentError, "Invalid package name or version: #{name_str} #{version}"
    end

    tmp_dir = Path.join(System.tmp_dir!(), "vet_diff_#{name_str}_#{version}")

    if File.dir?(tmp_dir) do
      tmp_dir
    else
      case System.cmd("mix", ["hex.package", "fetch", name_str, version, "--output", tmp_dir],
             stderr_to_stdout: true
           ) do
        {_output, 0} -> tmp_dir
        _ -> nil
      end
    end
  end

  defp list_source_files(dir) do
    Path.wildcard(Path.join([dir, "**", "*.{ex,exs}"]))
  end

  defp relative_path(full_path, base_dir) do
    String.replace_prefix(full_path, base_dir <> "/", "")
  end

  defp hash_file(path) do
    case File.read(path) do
      {:ok, content} -> :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
      {:error, _} -> nil
    end
  end
end
