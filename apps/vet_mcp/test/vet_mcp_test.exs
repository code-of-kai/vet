defmodule VetMcpTest do
  use ExUnit.Case

  describe "tools/0" do
    test "returns list of tool modules" do
      tools = VetMcp.tools()
      assert is_list(tools)
      assert length(tools) == 3
      assert VetMcp.Tools.GetSecurityFindings in tools
      assert VetMcp.Tools.CheckPackage in tools
      assert VetMcp.Tools.DiffPackageVersions in tools
    end
  end

  describe "tool_definitions/0" do
    test "returns definitions for all tools" do
      definitions = VetMcp.tool_definitions()
      assert length(definitions) == 3

      names = Enum.map(definitions, & &1.name)
      assert "vet_scan_dependencies" in names
      assert "vet_check_package" in names
      assert "vet_diff_versions" in names
    end

    test "each definition has required keys" do
      for def <- VetMcp.tool_definitions() do
        assert is_binary(def.name)
        assert is_binary(def.description)
        assert is_map(def.schema)
        assert def.schema.type == "object"
        assert is_atom(def.module)
      end
    end
  end

  describe "VetMcp.Tool behaviour" do
    test "GetSecurityFindings implements the behaviour" do
      mod = VetMcp.Tools.GetSecurityFindings
      assert mod.name() == "vet_scan_dependencies"
      assert is_binary(mod.description())
      assert %{type: "object", properties: props} = mod.schema()
      assert Map.has_key?(props, :path)
      assert Map.has_key?(props, :skip_hex)
      assert Map.has_key?(props, :threshold)
    end

    test "CheckPackage implements the behaviour" do
      mod = VetMcp.Tools.CheckPackage
      assert mod.name() == "vet_check_package"
      assert is_binary(mod.description())
      assert %{type: "object", required: ["package"], properties: props} = mod.schema()
      assert Map.has_key?(props, :package)
      assert Map.has_key?(props, :version)
    end

    test "DiffPackageVersions implements the behaviour" do
      mod = VetMcp.Tools.DiffPackageVersions
      assert mod.name() == "vet_diff_versions"
      assert is_binary(mod.description())

      assert %{type: "object", required: required, properties: props} = mod.schema()
      assert "package" in required
      assert "from_version" in required
      assert "to_version" in required
      assert Map.has_key?(props, :package)
      assert Map.has_key?(props, :from_version)
      assert Map.has_key?(props, :to_version)
    end

    test "CheckPackage returns error for missing package param" do
      assert {:error, _} = VetMcp.Tools.CheckPackage.execute(%{}, %{})
    end

    test "DiffPackageVersions returns error for missing params" do
      assert {:error, _} = VetMcp.Tools.DiffPackageVersions.execute(%{}, %{})
    end
  end

  describe "register/0" do
    test "returns error when Tidewave is not available" do
      assert {:error, :tidewave_not_loaded} = VetMcp.register()
    end
  end

  describe "tidewave_tools/0" do
    test "returns 3 tool maps in Tidewave format" do
      tools = VetMcp.tidewave_tools()
      assert length(tools) == 3

      for tool <- tools do
        assert is_binary(tool.name)
        assert is_binary(tool.description)
        assert is_map(tool.inputSchema)
        assert is_function(tool.callback, 1)
      end
    end
  end
end
