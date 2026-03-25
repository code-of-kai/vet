defmodule VetMcp do
  @moduledoc false

  def tools do
    [
      VetMcp.Tools.GetSecurityFindings,
      VetMcp.Tools.CheckPackage,
      VetMcp.Tools.DiffPackageVersions
    ]
  end
end
