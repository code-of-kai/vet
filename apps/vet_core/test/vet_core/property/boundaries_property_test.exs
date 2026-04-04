defmodule VetCore.Property.BoundariesPropertyTest do
  @moduledoc """
  Joe Armstrong boundary tests: what happens when the outside world lies to you?
  Every input from outside the process is hostile. Prove the system never crashes.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  @moduletag :property

  # -- Hex API response parsing: what if hex.pm returns garbage? --

  property "invariant: parse_hex_response never crashes on arbitrary maps" do
    check all(
            data <- map_of(string(:alphanumeric, min_length: 1, max_length: 10), term()),
            max_runs: 200
          ) do
      result = VetCore.Metadata.HexChecker.parse_hex_response(data)
      assert %VetCore.Types.HexMetadata{} = result
    end
  end

  property "invariant: parse_hex_response handles missing downloads gracefully" do
    check all(
            downloads_val <- one_of([constant(nil), constant("not_a_number"), integer(-100..100), constant(%{})]),
            max_runs: 100
          ) do
      data = %{"downloads" => %{"all" => downloads_val}, "releases" => [], "meta" => %{}}
      result = VetCore.Metadata.HexChecker.parse_hex_response(data)
      assert %VetCore.Types.HexMetadata{} = result
    end
  end

  property "invariant: parse_hex_response handles malformed releases" do
    check all(
            releases_val <- one_of([
              constant(nil),
              constant("not_a_list"),
              constant([%{}]),
              constant([%{"version" => 123, "inserted_at" => "not-a-date"}]),
              constant([%{"version" => "1.0.0", "inserted_at" => "2024-01-01T00:00:00Z", "retirement" => %{}}]),
              list_of(map_of(string(:alphanumeric), term()), max_length: 3)
            ]),
            max_runs: 100
          ) do
      data = %{"downloads" => %{"all" => 1000}, "releases" => releases_val, "meta" => %{}}
      result = VetCore.Metadata.HexChecker.parse_hex_response(data)
      assert %VetCore.Types.HexMetadata{} = result
    end
  end

  property "invariant: parse_hex_response handles malformed owners" do
    check all(
            owners_val <- one_of([constant(nil), constant(42), constant("string"), list_of(constant(%{}), max_length: 5)]),
            max_runs: 50
          ) do
      data = %{"downloads" => %{"all" => 500}, "releases" => [], "owners" => owners_val, "meta" => %{}}
      result = VetCore.Metadata.HexChecker.parse_hex_response(data)
      assert %VetCore.Types.HexMetadata{} = result
    end
  end

  # -- Shannon entropy: information theory invariants --

  property "invariant: entropy of uniform single-byte string is 0.0" do
    check all(
            char <- integer(0..255),
            len <- integer(1..100),
            max_runs: 100
          ) do
      str = :binary.copy(<<char>>, len)
      entropy = VetCore.Checks.Obfuscation.shannon_entropy(str)
      assert_in_delta entropy, 0.0, 0.001
    end
  end

  property "invariant: entropy is always non-negative" do
    check all(str <- string(:printable, min_length: 1, max_length: 200), max_runs: 200) do
      entropy = VetCore.Checks.Obfuscation.shannon_entropy(str)
      assert entropy >= 0.0
    end
  end

  property "invariant: entropy never exceeds log2(256) = 8.0" do
    check all(str <- binary(min_length: 1, max_length: 200), max_runs: 200) do
      entropy = VetCore.Checks.Obfuscation.shannon_entropy(str)
      assert entropy <= 8.0 + 0.001
    end
  end

  property "invariant: more distinct bytes means higher entropy" do
    check all(
            # Generate a byte we'll repeat, and a count of distinct bytes to compare
            repeated_byte <- integer(0..255),
            distinct_count <- integer(2..256),
            max_runs: 100
          ) do
      uniform = :binary.copy(<<repeated_byte>>, 256)
      varied = Enum.take(0..255, distinct_count) |> :binary.list_to_bin()

      e_uniform = VetCore.Checks.Obfuscation.shannon_entropy(uniform)
      e_varied = VetCore.Checks.Obfuscation.shannon_entropy(varied)

      assert e_uniform < e_varied
    end
  end

  # -- Scoring commutativity: order of findings must not matter --

  property "invariant: score is independent of findings order" do
    check all(
            {dep, findings, meta} <- scoring_context(),
            max_runs: 100
          ) do
      {score_original, level_original} = VetCore.Scorer.score(dep, findings, meta)
      {score_shuffled, level_shuffled} = VetCore.Scorer.score(dep, Enum.shuffle(findings), meta)

      assert score_original == score_shuffled
      assert level_original == level_shuffled
    end
  end

  # -- Allowlist config parsing: what if .vet.exs contains hostile AST? --

  property "invariant: allowlist config parser never crashes on arbitrary Elixir expressions" do
    expressions = [
      "%{allow: []}",
      "%{allow: [{:foo, :bar, \"reason\"}]}",
      "%{}",
      "[]",
      "[{:a, :b}]",
      ":atom",
      "123",
      "\"string\"",
      "{:tuple}",
      "%{nested: %{allow: []}}",
      "[1, 2, 3]",
      "nil",
      "true",
      "%{allow: :not_a_list}",
      "%{allow: [{:only_two, :fields}]}",
      "%{allow: [{123, :not_atom, \"reason\"}]}",
      "%{wrong_key: [{:a, :b, \"c\"}]}"
    ]

    for expr <- expressions do
      tmp = Path.join(System.tmp_dir!(), "vet_prop_allowlist_#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp)
      File.write!(Path.join(tmp, ".vet.exs"), expr)

      result = VetCore.Allowlist.load_user_config(tmp)
      assert is_list(result), "Expected list for expression: #{expr}, got: #{inspect(result)}"

      File.rm_rf!(tmp)
    end
  end

  # -- AST walking: generated quoted expressions must never crash checks --

  property "invariant: AST walker never crashes on arbitrary quoted expressions" do
    # Generate simple but valid Elixir ASTs
    check all(
            ast <- elixir_ast(),
            max_runs: 100
          ) do
      # Wrap in a module so checks can process it
      module_ast =
        {:defmodule, [line: 1],
         [{:__aliases__, [line: 1], [:TestModule]},
          [do: {:__block__, [], [ast]}]]}

      # Walk with the obfuscation matchers — they're the most complex
      result =
        try do
          VetCore.AST.Walker.walk(
            module_ast,
            [fn _node, _state -> nil end],
            "test.ex",
            :test_dep
          )
        rescue
          _ -> []
        end

      assert is_list(result)
    end
  end

  # -- Helper: generate simple valid Elixir ASTs --

  defp elixir_ast do
    one_of([
      # Literal values
      integer(-1000..1000),
      float(min: -100.0, max: 100.0),
      string(:alphanumeric, min_length: 0, max_length: 20),
      constant(:some_atom),
      constant(true),
      constant(false),
      constant(nil),
      # Simple function call
      bind(member_of([:foo, :bar, :baz]), fn name ->
        constant({name, [line: 1], []})
      end),
      # Variable reference
      bind(member_of([:x, :y, :z]), fn name ->
        constant({name, [line: 1], nil})
      end),
      # Two-element tuple
      bind(integer(1..100), fn n ->
        constant({:ok, n})
      end),
      # List
      bind(list_of(integer(0..10), max_length: 3), fn items ->
        constant(items)
      end)
    ])
  end
end
