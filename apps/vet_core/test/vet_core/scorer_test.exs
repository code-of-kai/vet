defmodule VetCore.ScorerTest do
  use ExUnit.Case

  alias VetCore.Scorer
  alias VetCore.Types.{Dependency, Finding, HexMetadata}

  test "scores a dependency with no findings as low risk" do
    dep = %Dependency{name: :safe_pkg, version: "1.0.0", source: :hex}
    metadata = %HexMetadata{downloads: 1_000_000, owner_count: 3}

    {score, level} = Scorer.score(dep, [], metadata)

    assert score < 20
    assert level == :low
  end

  test "scores compile-time critical findings heavily" do
    dep = %Dependency{name: :bad_pkg, version: "0.1.0", source: :hex}

    findings = [
      %Finding{
        dep_name: :bad_pkg,
        file_path: "lib/bad.ex",
        line: 1,
        check_id: :system_cmd,
        category: :system_exec,
        severity: :critical,
        compile_time?: true,
        description: "System.cmd in module body"
      }
    ]

    metadata = %HexMetadata{downloads: 50, owner_count: 1}

    {score, level} = Scorer.score(dep, findings, metadata)

    assert score >= 50
    assert level in [:high, :critical]
  end

  test "popularity adjustment reduces score for popular packages" do
    dep = %Dependency{name: :popular, version: "2.0.0", source: :hex}

    findings = [
      %Finding{
        dep_name: :popular,
        file_path: "lib/p.ex",
        line: 5,
        check_id: :file_read,
        category: :file_access,
        severity: :warning,
        compile_time?: false,
        description: "File.read!"
      }
    ]

    low_dl = %HexMetadata{downloads: 100, owner_count: 1}
    high_dl = %HexMetadata{downloads: 5_000_000, owner_count: 5}

    {low_score, _} = Scorer.score(dep, findings, low_dl)
    {high_score, _} = Scorer.score(dep, findings, high_dl)

    assert high_score < low_score
  end
end
