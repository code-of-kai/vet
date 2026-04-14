defmodule VetCore.ScanStore do
  @moduledoc false

  @scans_dir ".vet/scans"

  @doc """
  Save scan results for all dependencies in the report.
  Creates `.vet/scans/{package_name}.json` files, appending new version records
  and deduplicating by version.
  """
  def save(project_path, %{dependency_reports: reports}) do
    dir = scans_path(project_path)
    File.mkdir_p!(dir)

    Enum.each(reports, fn report ->
      dep = report.dependency
      record = build_record(report)
      file = package_file(dir, dep.name)

      history = read_json_file(file)
      updated = upsert_record(history, record)
      write_json_file(file, updated)
    end)

    :ok
  end

  @doc """
  Load scan history for a single package.
  Returns a list of version_record maps suitable for TemporalReputation.build/2.
  """
  def load_history(project_path, package_name) do
    dir = scans_path(project_path)
    file = package_file(dir, package_name)

    file
    |> read_json_file()
    |> Enum.map(&deserialize_record/1)
  end

  @doc """
  Load scan history for all packages in `.vet/scans/`.
  Returns a map of `%{package_name => [version_record]}`.
  """
  def load_all(project_path) do
    dir = scans_path(project_path)

    case File.ls(dir) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Map.new(fn file ->
          name = file |> String.trim_trailing(".json") |> String.to_atom()
          records = read_json_file(Path.join(dir, file)) |> Enum.map(&deserialize_record/1)
          {name, records}
        end)

      {:error, _} ->
        %{}
    end
  end

  # -- Private -----------------------------------------------------------------

  defp scans_path(project_path), do: Path.join(project_path, @scans_dir)

  defp package_file(dir, name), do: Path.join(dir, "#{name}.json")

  defp build_record(report) do
    categories =
      report.findings
      |> Enum.map(& &1.category)
      |> Enum.uniq()
      |> Enum.map(&Atom.to_string/1)

    %{
      "version" => report.dependency.version,
      "scan_date" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "finding_count" => length(report.findings),
      "categories" => categories,
      "risk_score" => report.risk_score
    }
  end

  defp upsert_record(history, record) do
    case Enum.find_index(history, &(&1["version"] == record["version"])) do
      nil -> history ++ [record]
      idx -> List.replace_at(history, idx, record)
    end
  end

  defp deserialize_record(map) do
    scan_date =
      case DateTime.from_iso8601(map["scan_date"] || "") do
        {:ok, dt, _offset} -> dt
        _ -> DateTime.utc_now()
      end

    %{
      version: map["version"],
      scan_date: scan_date,
      finding_count: map["finding_count"] || 0,
      categories: Enum.map(map["categories"] || [], &String.to_existing_atom/1),
      risk_score: map["risk_score"] || 0
    }
  rescue
    ArgumentError -> %{
      version: map["version"],
      scan_date: DateTime.utc_now(),
      finding_count: map["finding_count"] || 0,
      categories: [],
      risk_score: map["risk_score"] || 0
    }
  end

  defp read_json_file(path) do
    case File.read(path) do
      {:ok, contents} ->
        case Jason.decode(contents) do
          {:ok, list} when is_list(list) -> list
          _ -> []
        end

      {:error, _} ->
        []
    end
  end

  defp write_json_file(path, data) do
    File.write!(path, Jason.encode!(data, pretty: true))
  end
end
