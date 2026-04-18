defmodule VetCore.Metadata.TyposquatDetector do
  @moduledoc false

  alias VetCore.Types.Finding

  # Top ~200 Elixir/Hex packages by adoption. Used as reference corpus
  # for typosquat and slopsquat detection. Attackers register names that
  # are close to these — catching edit-distance-1 variants catches both
  # traditional typosquatting and LLM-hallucinated "slopsquatting" names.
  @top_packages ~w(
    phoenix ecto plug jason poison tesla req httpoison hackney
    phoenix_html phoenix_live_view phoenix_live_dashboard phoenix_pubsub
    phoenix_ecto telemetry telemetry_metrics telemetry_poller
    swoosh bamboo oban broadway
    absinthe absinthe_plug absinthe_phoenix absinthe_relay
    ex_machina faker stream_data
    credo dialyxir ex_doc
    postgrex myxql ecto_sql
    gettext mime plug_cowboy bandit cowboy cowlib ranch
    nimble_csv nimble_parsec nimble_options nimble_pool nimble_totp
    floki finch mint castore
    guardian comeonin bcrypt_elixir argon2_elixir pbkdf2_elixir
    timber logger_json
    excoveralls mix_test_watch
    rustler elixir_make
    earmark earmark_parser makeup makeup_elixir
    decimal uuid elixir_uuid
    membrane_core nx explorer evision bumblebee
    ash ash_postgres ash_phoenix ash_json_api ash_graphql ash_authentication
    commanded eventstore
    surface live_view_native
    kino livebook

    plug_crypto phoenix_swoosh phoenix_live_reload
    ecto_dev_logger ecto_psql_extras ecto_enum
    cors_plug plug_static_index_html

    ex_aws ex_aws_s3 ex_aws_ses ex_aws_sqs ex_aws_sns ex_aws_ec2
    stripity_stripe braintree_elixir

    timex tzdata calendar

    mox bypass hammox meck
    ex_unit_notifier mix_test_interactive wallaby hound flaky_test_detector

    sentry appsignal new_relic_agent
    logger_file_backend logger_papertrail_backend

    flow gen_stage
    cachex con_cache nebulex

    httpoison tesla_middleware_logger
    grpc protobuf google_protos

    bamboo_smtp bamboo_ses gen_smtp

    pow coherence ueberauth ueberauth_google ueberauth_github
    assent

    yaml_elixir toml sweet_xml saxy

    torch ex_admin kaffy backpex

    libcluster horde swarm

    dialyzex gradient type_check

    waffle arc waffle_ecto

    sobelow mix_audit

    redix
    mongodb_driver

    commanded_ecto_projections commanded_eventstore_adapter

    phoenix_slime phoenix_markdown slime

    premailex

    ex_cldr ex_cldr_numbers ex_cldr_dates_times ex_money

    elixir_ls next_ls lexical

    openai instructor

    igniter spark reactor

    open_api_spex

    tailwind esbuild dart_sass

    wallaby floki req_s3

    quantum

    briefly temp

    nanoid hashids

    fun_with_flags
  )a

  def check(deps) when is_list(deps) do
    Enum.flat_map(deps, fn dep ->
      check_dep(dep)
    end)
  end

  @doc """
  Returns the top-packages corpus. Used by PatchOracle to suggest the nearest
  verified replacement for a phantom or typosquatted package name.
  """
  @spec top_packages() :: [atom()]
  def top_packages, do: @top_packages

  @doc """
  Returns the closest known package to `name` by Levenshtein distance, or
  `:none` if nothing is within `max_distance`. Ties break by first match
  in the corpus order.
  """
  @spec nearest_known(atom() | String.t(), pos_integer()) ::
          {:ok, atom(), non_neg_integer()} | :none
  def nearest_known(name, max_distance \\ 2) do
    name_str = to_string(name)

    @top_packages
    |> Enum.reduce({nil, nil}, fn pkg, {best, best_dist} ->
      d = levenshtein(name_str, to_string(pkg))

      cond do
        d > max_distance -> {best, best_dist}
        is_nil(best_dist) or d < best_dist -> {pkg, d}
        true -> {best, best_dist}
      end
    end)
    |> case do
      {nil, nil} -> :none
      {pkg, dist} -> {:ok, pkg, dist}
    end
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
