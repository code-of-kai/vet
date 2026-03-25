defmodule VetWebTest do
  use ExUnit.Case

  test "VetWeb module exists" do
    assert Code.ensure_loaded?(VetWeb)
  end

  test "VetWeb defines static_paths" do
    assert is_list(VetWeb.static_paths())
  end

  test "VetWeb defines verified_routes" do
    Code.ensure_loaded!(VetWeb)
    assert function_exported?(VetWeb, :verified_routes, 0)
  end
end
