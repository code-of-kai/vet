defmodule VetCore.Checks.CoverageTest do
  @moduledoc """
  Table-driven coverage test: every `{module, function}` pattern that a check
  claims to detect must actually produce a finding when a synthetic source file
  calls it.

  This exists to catch the class of regression that let GH issues #7, #8, #9
  slip through originally: a maintainer deletes or renames an entry in a
  check's lookup table, the unit tests still pass because each is written
  for a specific pattern, and the deleted pattern is silently ignored.

  When adding a new pattern to a check module, add a corresponding row to the
  `@coverage` table below.
  """

  use ExUnit.Case

  alias VetCore.Checks.{CodeEval, FileAccess, NetworkAccess}
  alias VetCore.Types.Dependency

  # {check_module, call_source, description_substring}
  @coverage [
    # --- CodeEval ---
    {CodeEval, ~s|Code.eval_string("x")|, "Code.eval_string"},
    {CodeEval, ~s|Code.eval_quoted(quote do: 1)|, "Code.eval_quoted"},
    {CodeEval, ~s|Code.eval_file("x.exs")|, "Code.eval_file"},
    {CodeEval, ~s|Code.compile_string("x")|, "Code.compile_string"},
    {CodeEval, ~s|Code.compile_quoted(quote do: 1)|, "Code.compile_quoted"},
    {CodeEval, ~s|:erlang.binary_to_term(bin)|, ":erlang.binary_to_term"},
    {CodeEval, ~s|Module.create(M, (quote do: nil), __ENV__)|, "Module.create"},
    # GH #4
    {CodeEval, ~s|:compile.file(~c"x.erl", [])|, ":compile.file"},
    {CodeEval, ~s|:compile.forms(forms, [])|, ":compile.forms"},
    {CodeEval, ~s|:compile.file_binary(~c"x.erl", [])|, ":compile.file_binary"},
    {CodeEval, ~s|:compile.noenv_file(path, [])|, ":compile.noenv_file"},
    {CodeEval, ~s|:compile.noenv_forms(forms, [])|, ":compile.noenv_forms"},

    # --- FileAccess (Elixir File) ---
    {FileAccess, ~s|File.read!(path)|, "File.read!"},
    {FileAccess, ~s|File.write!(path, data)|, "File.write!"},
    {FileAccess, ~s|File.stream!(path)|, "File.stream!"},
    {FileAccess, ~s|File.rm(path)|, "File.rm"},
    {FileAccess, ~s|File.rm_rf(path)|, "File.rm_rf"},
    {FileAccess, ~s|File.read(path)|, "File.read"},
    {FileAccess, ~s|File.write(path, data)|, "File.write"},
    {FileAccess, ~s|File.cp(a, b)|, "File.cp"},
    {FileAccess, ~s|File.cp_r(a, b)|, "File.cp_r"},
    # GH #5
    {FileAccess, ~s|File.open!(path)|, "File.open!"},
    {FileAccess, ~s|File.open(path)|, "File.open"},

    # --- FileAccess (Erlang :file) — GH #6 ---
    {FileAccess, ~s|:file.read_file(path)|, ":file.read_file"},
    {FileAccess, ~s|:file.read_file_info(path)|, ":file.read_file_info"},
    {FileAccess, ~s|:file.consult(path)|, ":file.consult"},
    {FileAccess, ~s|:file.open(path, [:read])|, ":file.open"},
    {FileAccess, ~s|:file.list_dir(path)|, ":file.list_dir"},
    {FileAccess, ~s|:file.read_link(path)|, ":file.read_link"},
    {FileAccess, ~s|:file.script(path)|, ":file.script"},

    # --- NetworkAccess (specific) ---
    {NetworkAccess, ~s|:httpc.request(url)|, ":httpc.request"},
    {NetworkAccess, ~s|:gen_tcp.connect(host, port, [])|, ":gen_tcp.connect"},
    {NetworkAccess, ~s|:ssl.connect(host, port, [])|, ":ssl.connect"},
    # GH #7
    {NetworkAccess, ~s|:gen_tcp.listen(0, [])|, ":gen_tcp.listen"},
    {NetworkAccess, ~s|:gen_tcp.accept(sock)|, ":gen_tcp.accept"},
    {NetworkAccess, ~s|:gen_tcp.controlling_process(sock, pid)|, ":gen_tcp.controlling_process"},
    {NetworkAccess, ~s|:ssl.listen(port, [])|, ":ssl.listen"},
    {NetworkAccess, ~s|:ssl.accept(sock)|, ":ssl.accept"},
    # GH #8
    {NetworkAccess, ~s|:gen_udp.open(0, [])|, ":gen_udp.open"},
    {NetworkAccess, ~s|:gen_udp.connect(sock, addr, port)|, ":gen_udp.connect"},
    {NetworkAccess, ~s|:gen_udp.send(sock, addr, port, data)|, ":gen_udp.send"},
    {NetworkAccess, ~s|:gen_udp.recv(sock, n)|, ":gen_udp.recv"},
    {NetworkAccess, ~s|:gen_sctp.open([])|, ":gen_sctp.open"},
    {NetworkAccess, ~s|:gen_sctp.connect(sock, addr, port, opts)|, ":gen_sctp.connect"},
    {NetworkAccess, ~s|:gen_sctp.listen(sock, true)|, ":gen_sctp.listen"},
    {NetworkAccess, ~s|:gen_sctp.send(sock, assoc, stream, data)|, ":gen_sctp.send"},
    {NetworkAccess, ~s|:gen_sctp.recv(sock)|, ":gen_sctp.recv"},
    # GH #9 — :socket module is wildcard; verify representative calls fire.
    {NetworkAccess, ~s|:socket.open(:inet, :stream)|, ":socket"},
    {NetworkAccess, ~s|:socket.bind(sock, addr)|, ":socket"},
    {NetworkAccess, ~s|:socket.listen(sock)|, ":socket"},
    {NetworkAccess, ~s|:socket.accept(sock)|, ":socket"},
    {NetworkAccess, ~s|:socket.connect(sock, addr)|, ":socket"},
    {NetworkAccess, ~s|:socket.send(sock, data)|, ":socket"},
    {NetworkAccess, ~s|:socket.sendto(sock, data, dest)|, ":socket"},
    {NetworkAccess, ~s|:socket.recv(sock)|, ":socket"},

    # --- NetworkAccess (wildcard modules) ---
    {NetworkAccess, ~s|Req.get(url)|, "Req"},
    {NetworkAccess, ~s|HTTPoison.post(url, body)|, "HTTPoison"},
    {NetworkAccess, ~s|Finch.request(req, MyFinch)|, "Finch"},
    {NetworkAccess, ~s|Mint.HTTP.connect(:https, host, port)|, "Mint.HTTP"}
  ]

  setup do
    tmp_dir =
      Path.join(
        System.tmp_dir!(),
        "vet_coverage_test_#{:erlang.unique_integer([:positive])}"
      )

    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])
    File.mkdir_p!(dep_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    %{tmp_dir: tmp_dir, dep_dir: dep_dir}
  end

  defp run_check(check_module, tmp_dir, call_source) do
    dep_dir = Path.join([tmp_dir, "deps", "test_dep", "lib"])

    source = """
    defmodule Vet.CoverageFixture do
      def call(arg, a, b, c, addr, port, bin, body, req, dest, assoc, stream, sock, data, url, host, pid, n, forms, path, opts) do
        _ = {arg, a, b, c, addr, port, bin, body, req, dest, assoc, stream, sock, data, url, host, pid, n, forms, path, opts}
        #{call_source}
      end
    end
    """

    file = Path.join(dep_dir, "fixture.ex")
    File.write!(file, source)

    dep = %Dependency{name: :test_dep, version: "1.0.0", source: :hex}
    findings = check_module.run(dep, tmp_dir, [])

    File.rm!(file)
    findings
  end

  for {check_module, call_source, description_substring} <- @coverage do
    test "coverage: #{inspect(check_module)} fires on `#{call_source}`", %{tmp_dir: tmp_dir} do
      findings = run_check(unquote(check_module), tmp_dir, unquote(call_source))

      assert Enum.any?(findings, &(&1.description =~ unquote(description_substring))),
             "expected #{inspect(unquote(check_module))} to produce a finding " <>
               "matching #{inspect(unquote(description_substring))} for call " <>
               "`#{unquote(call_source)}`, but got: " <>
               inspect(Enum.map(findings, & &1.description))
    end
  end
end
