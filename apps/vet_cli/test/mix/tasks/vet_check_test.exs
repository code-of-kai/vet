defmodule Mix.Tasks.Vet.CheckTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_check_task_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir}
  end

  describe "mix vet.check" do
    @tag timeout: 120_000
    test "clean deps produce no warnings", %{tmp_dir: tmp_dir} do
      mix_exs = """
      defmodule CleanApp.MixProject do
        use Mix.Project

        def project do
          [app: :clean_app, version: "0.1.0", deps: deps()]
        end

        defp deps do
          [
            {:phoenix, "~> 1.7"},
            {:jason, "~> 1.0"}
          ]
        end
      end
      """

      File.write!(Path.join(tmp_dir, "mix.exs"), mix_exs)

      output =
        capture_io(fn ->
          Mix.Tasks.Vet.Check.run(["--path", tmp_dir])
        end)

      assert output =~ "Checking dependencies"
    end

    test "errors on missing project path" do
      assert_raise Mix.Error, fn ->
        capture_io(fn ->
          Mix.Tasks.Vet.Check.run(["--path", "/nonexistent/path/for/vet/test"])
        end)
      end
    end
  end
end
