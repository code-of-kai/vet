defmodule VetCore.Checks.NetworkAccess do
  @moduledoc false
  use VetCore.Check

  alias VetCore.AST.Walker
  alias VetCore.Checks.FileHelper
  alias VetCore.Types.Finding

  @category :network_access
  @base_severity :warning

  # Specific function patterns
  @specific_patterns [
    {[:httpc], :request},
    {[:gen_tcp], :connect},
    # TCP server-side — GH issue #7.
    {[:gen_tcp], :listen},
    {[:gen_tcp], :accept},
    {[:gen_tcp], :controlling_process},
    {[:ssl], :connect},
    {[:ssl], :listen},
    {[:ssl], :accept},
    # UDP — GH issue #8.
    {[:gen_udp], :open},
    {[:gen_udp], :connect},
    {[:gen_udp], :send},
    {[:gen_udp], :recv},
    # SCTP — GH issue #8.
    {[:gen_sctp], :open},
    {[:gen_sctp], :connect},
    {[:gen_sctp], :listen},
    {[:gen_sctp], :send},
    {[:gen_sctp], :recv}
  ]

  # Module-wildcard patterns — any function on these modules is flagged.
  # `:socket` added for GH issue #9; it's the low-level OTP socket API
  # and every function in the module is network access.
  @wildcard_modules %{
    [:Req] => "Req",
    [:HTTPoison] => "HTTPoison",
    [:Finch] => "Finch",
    [:Mint, :HTTP] => "Mint.HTTP",
    [:socket] => ":socket"
  }

  @specific_descriptions %{
    {[:httpc], :request} => "Call to :httpc.request — makes an HTTP request via Erlang's httpc",
    {[:gen_tcp], :connect} => "Call to :gen_tcp.connect — opens a raw TCP connection",
    {[:gen_tcp], :listen} =>
      "Call to :gen_tcp.listen — opens a TCP server socket",
    {[:gen_tcp], :accept} =>
      "Call to :gen_tcp.accept — accepts an incoming TCP connection",
    {[:gen_tcp], :controlling_process} =>
      "Call to :gen_tcp.controlling_process — transfers ownership of a TCP socket",
    {[:ssl], :connect} => "Call to :ssl.connect — opens an SSL/TLS connection",
    {[:ssl], :listen} => "Call to :ssl.listen — opens an SSL/TLS server socket",
    {[:ssl], :accept} => "Call to :ssl.accept — accepts an incoming TLS connection",
    {[:gen_udp], :open} => "Call to :gen_udp.open — opens a UDP socket",
    {[:gen_udp], :connect} => "Call to :gen_udp.connect — associates a UDP socket with a peer",
    {[:gen_udp], :send} => "Call to :gen_udp.send — sends a UDP datagram",
    {[:gen_udp], :recv} => "Call to :gen_udp.recv — receives a UDP datagram",
    {[:gen_sctp], :open} => "Call to :gen_sctp.open — opens an SCTP socket",
    {[:gen_sctp], :connect} => "Call to :gen_sctp.connect — opens an SCTP association",
    {[:gen_sctp], :listen} => "Call to :gen_sctp.listen — marks an SCTP socket as server",
    {[:gen_sctp], :send} => "Call to :gen_sctp.send — sends an SCTP message",
    {[:gen_sctp], :recv} => "Call to :gen_sctp.recv — receives an SCTP message"
  }

  @doc """
  Returns every pattern this check detects. Specific patterns are returned as
  `{module_segments, function_atom}`. Wildcard modules (where any function call
  fires a finding) are returned as `{module_segments, :*}`.

  Exposed so the coverage sweep test in
  `apps/vet_core/test/vet_core/checks/coverage_test.exs` can assert the
  declared target list and the swept calls are exactly equal. Wildcard
  modules are satisfied by any coverage row whose module matches.
  """
  def target_patterns do
    wildcards = for {segs, _name} <- @wildcard_modules, do: {segs, :*}
    @specific_patterns ++ wildcards
  end

  @impl true
  def run(%{name: dep_name} = _dependency, project_path, state) do
    dep_name
    |> FileHelper.parsed_files(project_path, state)
    |> Enum.flat_map(fn {file_path, source, ast} ->
      Walker.walk(ast, [&matcher(&1, &2, dep_name, source)], file_path, dep_name)
    end)
  end

  defp matcher(node, state, dep_name, source) do
    with {_type, module, func, _args, meta} <- Walker.resolve_call(node, state),
         {true, description} <- classify(module, func) do
      is_ct = FileHelper.compile_time?(state.context_stack)
      severity = if is_ct, do: :critical, else: @base_severity
      line = meta[:line] || 0

      %Finding{
        dep_name: dep_name,
        file_path: state.file_path,
        line: line,
        column: meta[:column],
        check_id: :network_access,
        category: @category,
        severity: severity,
        compile_time?: is_ct,
        snippet: FileHelper.snippet(source, line),
        description: description
      }
    else
      _ -> nil
    end
  end

  defp classify(module, func) do
    cond do
      matches_specific?(module, func) ->
        desc = Map.fetch!(@specific_descriptions, {module, func})
        {true, desc}

      Map.has_key?(@wildcard_modules, module) ->
        lib_name = Map.fetch!(@wildcard_modules, module)

        desc =
          if module == [:Mint, :HTTP] do
            "Call to #{lib_name}.#{func} — low-level HTTP client call"
          else
            "Call to #{lib_name}.#{func} — HTTP client library call"
          end

        {true, desc}

      true ->
        false
    end
  end

  defp matches_specific?(module, func) do
    Enum.any?(@specific_patterns, fn {m, f} -> m == module and f == func end)
  end
end
