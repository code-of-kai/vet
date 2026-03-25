defmodule VetCore.Wiring.TypesTest do
  use ExUnit.Case, async: true

  alias VetCore.Types.{Dependency, Finding, DependencyReport, ScanReport}

  describe "Dependency struct" do
    test "has required field :name" do
      assert_raise ArgumentError, fn ->
        struct!(Dependency, %{})
      end
    end

    test "can be created with :name" do
      dep = %Dependency{name: :my_dep}
      assert dep.name == :my_dep
    end
  end

  describe "Finding struct" do
    test "has required fields" do
      required = [:dep_name, :file_path, :line, :check_id, :category, :severity, :description]

      for field <- required do
        # Remove one required field and verify it raises
        all_fields =
          Map.new(required, fn
            ^field -> {field, nil}
            f -> {f, :placeholder}
          end)
          |> Map.delete(field)

        assert_raise ArgumentError, fn ->
          struct!(Finding, all_fields)
        end
      end
    end

    test "can be created with all required fields" do
      finding = %Finding{
        dep_name: :test_dep,
        file_path: "lib/test.ex",
        line: 1,
        check_id: :system_exec,
        category: :system_exec,
        severity: :critical,
        description: "test finding"
      }

      assert finding.dep_name == :test_dep
    end
  end

  describe "DependencyReport struct" do
    test "defaults findings to []" do
      report = %DependencyReport{}
      assert report.findings == []
    end
  end

  describe "ScanReport struct" do
    test "defaults dependency_reports to []" do
      report = %ScanReport{}
      assert report.dependency_reports == []
    end
  end
end
