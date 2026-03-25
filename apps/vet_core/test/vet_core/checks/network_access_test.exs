defmodule VetCore.Checks.NetworkAccessTest do
  use ExUnit.Case

  alias VetCore.Checks.NetworkAccess
  alias VetCore.Types.Dependency

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "vet_network_test_#{:erlang.unique_integer([:positive])}")
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(tmp_dir, source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.write!(Path.join(dep_dir, "module.ex"), source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    NetworkAccess.run(dep, tmp_dir, [])
  end

  test "detects :httpc.request", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def fetch(url) do
        :httpc.request(url)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ ":httpc.request"
    assert hd(findings).category == :network_access
  end

  test "detects :gen_tcp.connect", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def connect do
        :gen_tcp.connect(~c"localhost", 8080, [])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ ":gen_tcp.connect"
  end

  test "detects :ssl.connect", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def connect do
        :ssl.connect(~c"example.com", 443, [])
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ ":ssl.connect"
  end

  test "detects Req.get", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def fetch(url) do
        Req.get(url)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Req.get"
  end

  test "detects Req.post", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def send_data(url, body) do
        Req.post(url, body: body)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Req.post"
  end

  test "detects HTTPoison.get", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def fetch(url) do
        HTTPoison.get(url)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "HTTPoison.get"
  end

  test "detects HTTPoison.post", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def send(url, body) do
        HTTPoison.post(url, body)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "HTTPoison.post"
  end

  test "detects Finch.request", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def fetch(req) do
        Finch.request(req, MyFinch)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Finch.request"
  end

  test "detects Mint.HTTP.connect", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def connect do
        Mint.HTTP.connect(:https, "example.com", 443)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    assert length(findings) >= 1
    assert hd(findings).description =~ "Mint.HTTP.connect"
  end

  test "no false positives on benign code (baseline)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule SafeMod do
      def hello, do: :world
      def process(data), do: String.upcase(data)
    end
    """

    findings = run_check(tmp_dir, source)

    assert findings == []
  end

  test "runtime network access gets :warning severity", %{tmp_dir: tmp_dir} do
    source = """
    defmodule TestMod do
      def fetch(url) do
        :httpc.request(url)
      end
    end
    """

    findings = run_check(tmp_dir, source)

    rt_findings = Enum.reject(findings, & &1.compile_time?)
    assert length(rt_findings) >= 1
    assert hd(rt_findings).severity == :warning
  end
end
