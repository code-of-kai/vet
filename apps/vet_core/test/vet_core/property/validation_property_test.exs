defmodule VetCore.Property.ValidationPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import VetCore.Generators

  alias VetCore.PreInstallCheck

  @moduletag :property

  # -- Package name validation --

  property "invariant: valid package names always produce {:ok, atom}" do
    check all(name <- package_name_string(), max_runs: 200) do
      assert {:ok, atom} = PreInstallCheck.validate_package_name(name)
      assert is_atom(atom)
      assert to_string(atom) == name
    end
  end

  property "invariant: uppercase strings always rejected" do
    check all(
            first <- member_of(Enum.to_list(?A..?Z)),
            rest <- string(:alphanumeric, min_length: 0, max_length: 20),
            max_runs: 100
          ) do
      name = <<first>> <> rest
      assert {:error, _} = PreInstallCheck.validate_package_name(name)
    end
  end

  property "invariant: strings starting with digits always rejected" do
    check all(
            first <- member_of(Enum.to_list(?0..?9)),
            rest <- string(:alphanumeric, min_length: 0, max_length: 20),
            max_runs: 100
          ) do
      name = <<first>> <> rest
      assert {:error, _} = PreInstallCheck.validate_package_name(name)
    end
  end

  property "invariant: strings longer than 64 chars always rejected" do
    check all(
            len <- integer(65..200),
            max_runs: 50
          ) do
      name = "a" <> String.duplicate("b", len - 1)
      assert {:error, _} = PreInstallCheck.validate_package_name(name)
    end
  end

  property "invariant: empty string always rejected" do
    assert {:error, _} = PreInstallCheck.validate_package_name("")
  end

  property "invariant: strings with hyphens always rejected" do
    check all(
            left <- package_name_string(),
            right <- package_name_string(),
            max_runs: 100
          ) do
      name = left <> "-" <> right
      # May exceed 64 chars, but should fail either for hyphen or length
      assert {:error, _} = PreInstallCheck.validate_package_name(name)
    end
  end

  # -- Lock parser safety --

  property "invariant: lock parser never crashes on arbitrary strings" do
    check all(content <- string(:printable, min_length: 0, max_length: 500), max_runs: 100) do
      tmp = Path.join(System.tmp_dir!(), "vet_prop_#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp)
      File.write!(Path.join(tmp, "mix.lock"), content)

      result = VetCore.LockParser.parse(tmp)

      assert match?({:ok, _}, result) or match?({:error, _}, result)

      File.rm_rf!(tmp)
    end
  end
end
