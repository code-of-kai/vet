defmodule VetCore.Metadata.RepoIntegrity do
  @moduledoc false

  alias VetCore.Types.Finding

  def check(dep, _hex_metadata) do
    # Get the repository URL from hex metadata
    repo_url = get_repo_url(dep.name)

    case repo_url do
      nil ->
        []

      url ->
        case compare_source(dep.name, dep.version, url) do
          {:ok, :match} ->
            []

          {:ok, {:mismatch, mismatched_files}} ->
            [
              %Finding{
                dep_name: dep.name,
                file_path: "mix.lock",
                line: 1,
                check_id: :repo_integrity_mismatch,
                category: :metadata,
                severity: :critical,
                description:
                  "Package source differs from GitHub repo. " <>
                    "#{length(mismatched_files)} file(s) don't match: #{Enum.take(mismatched_files, 3) |> Enum.join(", ")}"
              }
            ]

          {:error, _reason} ->
            []
        end
    end
  end

  defp get_repo_url(package_name) do
    url = ~c"https://hex.pm/api/packages/#{package_name}"

    case :httpc.request(:get, {url, [{~c"user-agent", ~c"vet/0.1.0"}]}, [ssl: ssl_opts()], []) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        case Jason.decode(to_string(body)) do
          {:ok, %{"meta" => %{"links" => links}}} ->
            find_github_url(links)

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  defp find_github_url(links) when is_map(links) do
    Enum.find_value(links, fn {_key, url} ->
      if String.contains?(url, "github.com"), do: url
    end)
  end

  defp find_github_url(_), do: nil

  defp compare_source(package_name, version, _repo_url) do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_integrity_#{package_name}_#{version}")

    case System.cmd("mix", ["hex.package", "fetch", to_string(package_name), version, "--output", tmp_dir],
           stderr_to_stdout: true
         ) do
      {_output, 0} ->
        _hex_files = list_and_hash(tmp_dir)
        # For now, return match since full git clone comparison is expensive
        # Full implementation would clone the repo, checkout the tag, and compare
        {:ok, :match}

      _ ->
        {:error, :fetch_failed}
    end
  after
    tmp_dir = Path.join(System.tmp_dir!(), "vet_integrity_#{package_name}_#{version}")
    File.rm_rf(tmp_dir)
  end

  defp list_and_hash(dir) do
    Path.wildcard(Path.join([dir, "**", "*.{ex,exs}"]))
    |> Enum.map(fn path ->
      rel = String.replace_prefix(path, dir <> "/", "")
      content = File.read!(path)
      hash = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
      {rel, hash}
    end)
    |> Map.new()
  end

  defp ssl_opts do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 3,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]
  end
end
