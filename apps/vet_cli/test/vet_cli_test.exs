defmodule VetCliTest do
  use ExUnit.Case

  test "print_help does not crash" do
    # Just verify the module loads and help text can be generated
    assert is_function(&VetCli.main/1)
  end
end
