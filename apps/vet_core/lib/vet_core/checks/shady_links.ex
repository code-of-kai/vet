defmodule VetCore.Checks.ShadyLinks do
  @moduledoc false
  @behaviour VetCore.Check

  alias VetCore.Types.Finding

  @category :shady_links
  @base_severity :warning

  defp patterns do
    [
      {~r/https?:\/\/[^\s"']*\.xyz\//, "URL with suspicious TLD .xyz"},
      {~r/https?:\/\/[^\s"']*\.tk\//, "URL with suspicious TLD .tk"},
      {~r/https?:\/\/[^\s"']*\.ml\//, "URL with suspicious TLD .ml"},
      {~r/https?:\/\/[^\s"']*\.ga\//, "URL with suspicious TLD .ga"},
      {~r/https?:\/\/[^\s"']*\.cf\//, "URL with suspicious TLD .cf"},
      {~r/ngrok\.io/, "Reference to ngrok.io tunneling service"},
      {~r/serveo\.net/, "Reference to serveo.net tunneling service"},
      {~r/localhost\.run/, "Reference to localhost.run tunneling service"},
      {~r/pastebin\.com/, "Reference to pastebin.com — possible data exfiltration endpoint"},
      {~r/api\.telegram\.org/, "Reference to Telegram API — possible data exfiltration endpoint"},
      {~r/discord\.com\/api\/webhooks/, "Reference to Discord webhook — possible data exfiltration endpoint"},
      {~r/requestbin/i, "Reference to requestbin — possible data exfiltration endpoint"},
      {~r/https?:\/\/\d+\.\d+\.\d+\.\d+/, "Raw IP address URL — suspicious hardcoded IP endpoint"}
    ]
  end

  @impl true
  def init(opts), do: opts

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, _state) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    patterns = [
      Path.join([dep_dir, "lib", "**", "*.ex"]),
      Path.join([dep_dir, "lib", "**", "*.exs"]),
      Path.join([dep_dir, "mix.exs"])
    ]

    patterns
    |> Enum.flat_map(&Path.wildcard/1)
    |> Enum.uniq()
    |> Enum.reject(&in_test_directory?/1)
    |> Enum.flat_map(fn file_path ->
      case File.read(file_path) do
        {:ok, source} -> scan_source(source, dep_name, file_path)
        _ -> []
      end
    end)
  end

  defp scan_source(source, dep_name, file_path) do
    source
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reject(fn {line_text, _idx} -> comment_line?(line_text) end)
    |> Enum.flat_map(fn {line_text, line_number} ->
      Enum.flat_map(patterns(), fn {regex, description} ->
        if Regex.match?(regex, line_text) do
          [%Finding{
            dep_name: dep_name,
            file_path: file_path,
            line: line_number,
            column: nil,
            check_id: :shady_links,
            category: @category,
            severity: @base_severity,
            compile_time?: false,
            snippet: String.trim(line_text),
            description: description
          }]
        else
          []
        end
      end)
    end)
  end

  defp comment_line?(line) do
    line
    |> String.trim_leading()
    |> String.starts_with?("#")
  end

  defp in_test_directory?(path) do
    String.contains?(path, "/test/")
  end
end
