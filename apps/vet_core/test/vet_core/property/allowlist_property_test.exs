defmodule VetCore.Property.AllowlistPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.Allowlist

  @moduletag :property

  property "invariant: filter_findings never adds findings" do
    check all(
            dep_name <- package_name_atom(),
            findings <- list_of(finding(), min_length: 0, max_length: 10),
            max_runs: 100
          ) do
      findings = Enum.map(findings, fn f -> %{f | dep_name: dep_name} end)
      filtered = Allowlist.filter_findings(findings, dep_name, "/nonexistent")
      assert length(filtered) <= length(findings)
    end
  end

  property "invariant: filtered findings are a subset of original findings" do
    check all(
            dep_name <- package_name_atom(),
            findings <- list_of(finding(), min_length: 0, max_length: 10),
            max_runs: 100
          ) do
      findings = Enum.map(findings, fn f -> %{f | dep_name: dep_name} end)
      filtered = Allowlist.filter_findings(findings, dep_name, "/nonexistent")
      assert Enum.all?(filtered, fn f -> f in findings end)
    end
  end

  property "invariant: suppressed? is deterministic" do
    check all(
            dep_name <- package_name_atom(),
            cat <- category(),
            max_runs: 100
          ) do
      result1 = Allowlist.suppressed?(dep_name, cat)
      result2 = Allowlist.suppressed?(dep_name, cat)
      assert result1 == result2
    end
  end

  property "invariant: known allowlisted packages are suppressed" do
    known = [
      {:phoenix, :code_eval},
      {:ecto, :code_eval},
      {:rustler, :system_exec},
      {:plug, :env_access}
    ]

    for {pkg, cat} <- known do
      assert Allowlist.suppressed?(pkg, cat),
             "Expected #{pkg}:#{cat} to be suppressed"
    end
  end

  property "invariant: load_user_config returns list for nonexistent path" do
    check all(
            path <- string(:alphanumeric, min_length: 10, max_length: 30),
            max_runs: 50
          ) do
      result = Allowlist.load_user_config("/nonexistent/#{path}")
      assert is_list(result)
      assert result == []
    end
  end
end
