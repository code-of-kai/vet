defmodule VetCore.Checks.ShadyLinksTest do
  use ExUnit.Case

  alias VetCore.Checks.ShadyLinks
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_shady_links_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    ShadyLinks.run(dep, tmp_dir, [])
  end

  test "detects ngrok.io URLs", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @url "https://abc123.ngrok.io/callback"
      def url, do: @url
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "ngrok.io"
    assert hd(findings).check_id == :shady_links
    assert hd(findings).category == :shady_links
  end

  test "detects .xyz TLD URLs", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @url "https://evil-domain.xyz/payload"
      def url, do: @url
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ ".xyz"
  end

  test "detects pastebin.com references", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @url "https://pastebin.com/raw/abc123"
      def url, do: @url
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "pastebin.com"
  end

  test "detects raw IP URLs (http://1.2.3.4/...)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      @url "http://1.2.3.4/exfil"
      def url, do: @url
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Raw IP"
  end

  test "ignores comment lines (#)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      # This is a comment with ngrok.io reference
      def hello, do: :world
    end
    """

    findings = run_check(tmp_dir, source)

    ngrok_findings = Enum.filter(findings, &(&1.description =~ "ngrok"))
    assert ngrok_findings == []
  end

  test "ignores test directories", %{tmp_dir: tmp_dir} do
    # Create a file inside a test directory
    test_dir = Path.join([tmp_dir, "deps", "test_dep", "test"])
    File.mkdir_p!(test_dir)
    File.write!(Path.join(test_dir, "shady_test.ex"), """
    defmodule TestMod do
      @url "https://abc.ngrok.io/callback"
      def url, do: @url
    end
    """)

    # Also create an empty lib so the check runs
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)
    File.write!(Path.join(dep_dir, "safe.ex"), """
    defmodule SafeMod do
      def hello, do: :world
    end
    """)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    findings = ShadyLinks.run(dep, tmp_dir, [])

    # Should not find ngrok in test directory files
    ngrok_findings = Enum.filter(findings, &(&1.description =~ "ngrok"))
    assert ngrok_findings == []
  end

  test "no findings for benign code (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      @url "https://hexdocs.pm/elixir/Kernel.html"
      def hello, do: :world
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end
end
