defmodule VetMcpTest do
  use ExUnit.Case

  test "tools/0 returns list of tool modules" do
    tools = VetMcp.tools()
    assert is_list(tools)
    assert length(tools) == 3
    assert VetMcp.Tools.GetSecurityFindings in tools
  end
end
