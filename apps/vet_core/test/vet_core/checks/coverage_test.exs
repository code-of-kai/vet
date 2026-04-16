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
    {FileAccess, ~s|:file.read(sock, 100)|, ":file.read"},
    {FileAccess, ~s|:file.pread(sock, 0, 100)|, ":file.pread"},
    {FileAccess, ~s|:file.script(path)|, ":file.script"},
    {FileAccess, ~s|:file.path_consult([~c"a"], path)|, ":file.path_consult"},
    {FileAccess, ~s|:file.path_script([~c"a"], path)|, ":file.path_script"},
    {FileAccess, ~s|:file.list_dir(path)|, ":file.list_dir"},
    {FileAccess, ~s|:file.read_link(path)|, ":file.read_link"},
    {FileAccess, ~s|:file.write_file(path, data)|, ":file.write_file"},
    {FileAccess, ~s|:file.delete(path)|, ":file.delete"},
    {FileAccess, ~s|:file.del_dir(path)|, ":file.del_dir"},
    {FileAccess, ~s|:file.rename(a, b)|, ":file.rename"},
    {FileAccess, ~s|:file.make_link(a, b)|, ":file.make_link"},
    {FileAccess, ~s|:file.make_symlink(a, b)|, ":file.make_symlink"},

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

  # --- Symmetric equivalence tests ---
  #
  # The per-row tests above prove: every swept call fires. The tests below
  # prove the other direction: every declared target pattern in each check
  # module has at least one swept call, and every swept call corresponds to
  # a declared target pattern. Together these make the coverage table a
  # bijection with the check's target lists.
  #
  # Without this, someone can add `{[:Code], :new_danger}` to CodeEval's
  # `@patterns` and the old tests still pass; new_danger is technically
  # covered by whatever targeted test they wrote, but silently absent from
  # the exhaustive sweep. These assertions fail loudly in that case.

  describe "symmetric equivalence" do
    test "CodeEval declared patterns equal swept patterns" do
      assert_equivalent(CodeEval, CodeEval.target_patterns())
    end

    test "FileAccess declared patterns equal swept patterns" do
      assert_equivalent(FileAccess, FileAccess.target_patterns())
    end

    test "NetworkAccess declared patterns (specific + wildcard) equal swept patterns" do
      assert_equivalent(NetworkAccess, NetworkAccess.target_patterns())
    end
  end

  # Extract the `{module_segments, function_atom}` tuple from an Elixir call
  # source string. Handles both Elixir aliases (`Code.eval_string(...)`) and
  # Erlang atom modules (`:gen_tcp.listen(...)` or `:socket.open(...)`).
  defp extract_call(source) do
    case Code.string_to_quoted(source) do
      {:ok, {{:., _, [{:__aliases__, _, segs}, func]}, _, _}} ->
        {segs, func}

      {:ok, {{:., _, [mod_atom, func]}, _, _}} when is_atom(mod_atom) ->
        {[mod_atom], func}

      _ ->
        nil
    end
  end

  # Assert the declared target list and the swept call set are bijective
  # modulo wildcards. A wildcard `{segs, :*}` is satisfied by any swept
  # call whose module equals `segs`.
  defp assert_equivalent(check_module, declared_patterns) do
    swept_calls =
      for {mod, call, _desc} <- @coverage,
          mod == check_module,
          pair = extract_call(call),
          not is_nil(pair),
          do: pair

    swept_set = MapSet.new(swept_calls)
    declared_set = MapSet.new(declared_patterns)

    {wildcards, specifics} =
      Enum.split_with(declared_patterns, fn
        {_, :*} -> true
        _ -> false
      end)

    wildcard_modules = MapSet.new(wildcards, fn {segs, _} -> segs end)

    # Specific patterns must appear exactly in the sweep.
    specifics_set = MapSet.new(specifics)
    missing_from_sweep = MapSet.difference(specifics_set, swept_set)

    assert MapSet.size(missing_from_sweep) == 0,
           "#{inspect(check_module)} declares targets that have no swept call in @coverage: " <>
             inspect(MapSet.to_list(missing_from_sweep))

    # Every wildcard module must have at least one swept call.
    uncovered_wildcards =
      Enum.reject(wildcards, fn {segs, _} ->
        Enum.any?(swept_calls, fn {mod, _func} -> mod == segs end)
      end)

    assert uncovered_wildcards == [],
           "#{inspect(check_module)} declares wildcard modules with no swept call: " <>
             inspect(uncovered_wildcards)

    # Every swept call must be either a declared specific pattern or under a
    # declared wildcard module.
    unexplained =
      Enum.reject(swept_calls, fn {segs, func} = pair ->
        MapSet.member?(specifics_set, pair) or MapSet.member?(wildcard_modules, segs) or
          {segs, func} in declared_set
      end)

    assert unexplained == [],
           "#{inspect(check_module)} @coverage has swept calls that don't match any declared target: " <>
             inspect(unexplained)
  end
end
