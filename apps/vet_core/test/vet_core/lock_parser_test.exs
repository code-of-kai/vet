defmodule VetCore.LockParserTest do
  use ExUnit.Case

  alias VetCore.LockParser
  alias VetCore.Types.Dependency

  test "parses a real mix.lock file" do
    project_path = Path.expand("../../../../../git-foil", __DIR__)

    if File.exists?(Path.join(project_path, "mix.lock")) do
      assert {:ok, deps} = LockParser.parse(project_path)
      assert is_list(deps)
      assert length(deps) > 0

      # All deps should be Dependency structs
      Enum.each(deps, fn dep ->
        assert %Dependency{} = dep
        assert is_atom(dep.name)
      end)

      # Should find jason (a hex dep)
      jason = Enum.find(deps, &(&1.name == :jason))
      assert jason != nil
      assert jason.source == :hex
      assert jason.version != nil
    end
  end

  test "returns error for missing lock file" do
    assert {:error, {:lock_file, :enoent}} = LockParser.parse("/nonexistent")
  end
end
