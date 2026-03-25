defmodule VetMcp.Wiring.ToolBehaviourTest do
  use ExUnit.Case, async: true

  @tools [
    VetMcp.Tools.GetSecurityFindings,
    VetMcp.Tools.CheckPackage,
    VetMcp.Tools.DiffPackageVersions
  ]

  for tool <- @tools do
    describe "#{inspect(tool)}" do
      test "implements name/0 returning a string" do
        name = unquote(tool).name()
        assert is_binary(name)
        assert String.length(name) > 0
      end

      test "implements description/0 returning a non-empty string" do
        desc = unquote(tool).description()
        assert is_binary(desc)
        assert String.length(desc) > 0
      end

      test "implements schema/0 returning a map with :type key" do
        schema = unquote(tool).schema()
        assert is_map(schema)
        assert Map.has_key?(schema, :type)
      end

      test "implements execute/2" do
        Code.ensure_loaded!(unquote(tool))
        assert function_exported?(unquote(tool), :execute, 2)
      end
    end
  end

  describe "VetMcp.tools/0" do
    test "returns all 3 tool modules" do
      tools = VetMcp.tools()
      assert length(tools) == 3

      for tool <- @tools do
        assert tool in tools
      end
    end
  end

  describe "VetMcp.tool_definitions/0" do
    test "returns 3 maps with :name, :description, :schema, :module keys" do
      definitions = VetMcp.tool_definitions()
      assert length(definitions) == 3

      for definition <- definitions do
        assert is_map(definition)
        assert Map.has_key?(definition, :name)
        assert Map.has_key?(definition, :description)
        assert Map.has_key?(definition, :schema)
        assert Map.has_key?(definition, :module)
        assert is_binary(definition.name)
        assert is_binary(definition.description)
        assert is_map(definition.schema)
        assert definition.module in @tools
      end
    end
  end
end
