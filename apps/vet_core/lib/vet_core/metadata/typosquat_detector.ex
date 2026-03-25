defmodule VetCore.Metadata.TyposquatDetector do
  @moduledoc false

  alias VetCore.Types.Finding

  @top_packages ~w(
    phoenix ecto plug jason poison tesla req httpoison hackney
    phoenix_html phoenix_live_view phoenix_live_dashboard phoenix_pubsub
    phoenix_ecto telemetry telemetry_metrics telemetry_poller
    swoosh bamboo oban broadway
    absinthe absinthe_plug absinthe_phoenix
    ex_machina faker stream_data
    credo dialyxir ex_doc
    postgrex myxql ecto_sql
    gettext mime plug_cowboy bandit
    nimble_csv nimble_parsec nimble_options nimble_pool
    floki finch mint castore
    guardian comeonin bcrypt_elixir argon2_elixir
    timber logger_json
    excoveralls mix_test_watch
    rustler elixir_make
    earmark earmark_parser makeup
    decimal uuid
    membrane_core nx explorer evision bumblebee
    ash ash_postgres ash_phoenix ash_json_api
    commanded eventstore
    surface live_view_native
    kino livebook
  )a

  def check(deps) when is_list(deps) do
    Enum.flat_map(deps, fn dep ->
      check_dep(dep)
    end)
  end

  def check_dep(dep) do
    dep_str = to_string(dep.name)

    @top_packages
    |> Enum.reject(&(&1 == dep.name))
    |> Enum.flat_map(fn top_pkg ->
      top_str = to_string(top_pkg)

      cond do
        levenshtein(dep_str, top_str) == 1 ->
          [typosquat_finding(dep, top_pkg, "Levenshtein distance 1 from #{top_str}")]

        adjacent_swap?(dep_str, top_str) ->
          [typosquat_finding(dep, top_pkg, "Adjacent character swap of #{top_str}")]

        separator_confusion?(dep_str, top_str) ->
          [typosquat_finding(dep, top_pkg, "Separator confusion with #{top_str}")]

        true ->
          []
      end
    end)
  end

  defp typosquat_finding(dep, similar_to, reason) do
    %Finding{
      dep_name: dep.name,
      file_path: "mix.lock",
      line: 1,
      check_id: :typosquat,
      category: :metadata,
      severity: :warning,
      description: "Possible typosquat of :#{similar_to} — #{reason}"
    }
  end

  def levenshtein(s, t) do
    t_len = String.length(t)
    s_chars = String.graphemes(s)
    t_chars = String.graphemes(t)

    row = 0..t_len |> Enum.to_list()

    Enum.reduce(Enum.with_index(s_chars, 1), row, fn {s_char, i}, prev_row ->
      first = i

      Enum.reduce(Enum.with_index(t_chars, 1), {first, [first]}, fn {t_char, j}, {_prev_val, acc} ->
        cost = if s_char == t_char, do: 0, else: 1
        above = Enum.at(prev_row, j)
        left = List.last(acc)
        diag = Enum.at(prev_row, j - 1)
        val = Enum.min([above + 1, left + 1, diag + cost])
        {val, acc ++ [val]}
      end)
      |> elem(1)
    end)
    |> List.last()
  end

  defp adjacent_swap?(s, t) do
    s_len = String.length(s)
    t_len = String.length(t)

    if s_len != t_len do
      false
    else
      s_chars = String.graphemes(s)
      t_chars = String.graphemes(t)

      diffs =
        Enum.zip(s_chars, t_chars)
        |> Enum.with_index()
        |> Enum.filter(fn {{a, b}, _idx} -> a != b end)

      case diffs do
        [{{a1, b1}, i}, {{a2, b2}, j}] when j == i + 1 ->
          a1 == b2 and a2 == b1

        _ ->
          false
      end
    end
  end

  defp separator_confusion?(dep_str, top_str) do
    normalize = fn s ->
      s |> String.replace(~r/[-_.]/, "")
    end

    dep_str != top_str and normalize.(dep_str) == normalize.(top_str)
  end
end
