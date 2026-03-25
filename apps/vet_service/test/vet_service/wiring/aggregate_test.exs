defmodule VetService.Wiring.AggregateTest do
  use ExUnit.Case, async: true

  alias VetService.Aggregates.PackageVersion
  alias VetService.Commands.{ScanPackage, SubmitAttestation, SuppressFinding}

  describe "PackageVersion aggregate wiring" do
    test "module loads" do
      assert Code.ensure_loaded?(PackageVersion)
    end

    test "has execute/2 (Commanded aggregate callback)" do
      Code.ensure_loaded!(PackageVersion)
      assert function_exported?(PackageVersion, :execute, 2)
    end

    test "has apply/2 (Commanded aggregate callback)" do
      Code.ensure_loaded!(PackageVersion)
      assert function_exported?(PackageVersion, :apply, 2)
    end
  end

  describe "command structs exist and can be created" do
    test "ScanPackage struct" do
      assert Code.ensure_loaded?(ScanPackage)
      cmd = struct(ScanPackage)
      assert is_struct(cmd, ScanPackage)
    end

    test "SubmitAttestation struct" do
      assert Code.ensure_loaded?(SubmitAttestation)
      cmd = struct(SubmitAttestation)
      assert is_struct(cmd, SubmitAttestation)
    end

    test "SuppressFinding struct" do
      assert Code.ensure_loaded?(SuppressFinding)
      cmd = struct(SuppressFinding)
      assert is_struct(cmd, SuppressFinding)
    end
  end
end
