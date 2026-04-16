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

  # --- Regression tests for GH issues #7, #8, #9 ---
  # Each test uses the exact repro from the issue body.

  test "detects :gen_tcp.listen (GH #7)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo do
        :gen_tcp.listen(0, [])
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":gen_tcp.listen"))
  end

  test "detects :gen_tcp.accept (GH #7)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo(sock) do
        :gen_tcp.accept(sock)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":gen_tcp.accept"))
  end

  test "detects :gen_udp.open (GH #8)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo do
        :gen_udp.open(0, [])
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":gen_udp.open"))
  end

  test "detects :gen_udp.connect (GH #8)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo(sock) do
        :gen_udp.connect(sock, ~c"localhost", 53)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":gen_udp.connect"))
  end

  test "detects :gen_sctp.open (GH #8)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo do
        :gen_sctp.open([])
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":gen_sctp.open"))
  end

  test "detects :gen_sctp.listen (GH #8)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo(sock) do
        :gen_sctp.listen(sock, true)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":gen_sctp.listen"))
  end

  test "detects :socket.open (GH #9)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo do
        {:ok, s} = :socket.open(:inet, :stream)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":socket.open"))
  end

  test "detects :socket.bind (GH #9)", %{tmp_dir: tmp_dir} do
    source = """
    defmodule Foo do
      def foo(sock, addr) do
        :socket.bind(sock, addr)
      end
    end
    """

    findings = run_check(tmp_dir, source)
    assert Enum.any?(findings, &(&1.description =~ ":socket.bind"))
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
