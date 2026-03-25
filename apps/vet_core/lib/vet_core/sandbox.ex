defmodule VetCore.Sandbox do
  @moduledoc """
  Compiles a dependency in a traced environment to observe system calls made
  during compilation.

  NOTE: This module provides BEAM-level tracing only. For production use,
  dependencies should be compiled inside an OS-level sandbox (Docker, firejail,
  bubblewrap, etc.) to prevent actual damage from malicious compile-time code.
  The tracing approach here is useful for detection and reporting, not prevention.
  """

  @traced_mfas [
    {System, :cmd, 2},
    {System, :cmd, 3},
    {System, :shell, 1},
    {System, :shell, 2},
    {:httpc, :request, 1},
    {:httpc, :request, 4},
    {:httpc, :request, 5},
    {:gen_tcp, :connect, 3},
    {:gen_tcp, :connect, 4},
    {File, :write!, 2},
    {File, :write!, 3},
    {Port, :open, 2}
  ]

  @type trace_event :: %{
          module: module(),
          function: atom(),
          args_summary: String.t(),
          timestamp: DateTime.t()
        }

  @doc """
  Traces system calls made during compilation of the given dependency.

  Returns `{:ok, [trace_event]}` with a list of observed calls, or
  `{:error, reason}` if tracing setup or compilation fails.
  """
  @spec trace_compilation(atom(), String.t()) :: {:ok, [trace_event()]} | {:error, term()}
  def trace_compilation(dep_name, project_path) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    if File.dir?(dep_dir) do
      compile_in_sandbox(dep_name, project_path)
    else
      {:error, {:dep_not_found, dep_name, dep_dir}}
    end
  end

  @doc """
  Sets up trace handlers, runs compilation for the dependency, collects results,
  and tears down traces.
  """
  @spec compile_in_sandbox(atom(), String.t()) :: {:ok, [trace_event()]} | {:error, term()}
  def compile_in_sandbox(dep_name, project_path) do
    collector = start_collector()

    try do
      :ok = setup_traces(collector)
      _compile_result = do_compile(dep_name, project_path)
      events = collect_events(collector)
      {:ok, events}
    rescue
      e -> {:error, {:compilation_error, Exception.message(e)}}
    after
      teardown_traces()
      stop_collector(collector)
    end
  end

  # -- Collector process -------------------------------------------------------

  defp start_collector do
    {:ok, pid} = Agent.start_link(fn -> [] end)
    pid
  end

  defp stop_collector(pid) do
    Agent.stop(pid, :normal, 5_000)
  catch
    :exit, _ -> :ok
  end

  defp collect_events(pid) do
    Agent.get(pid, &Enum.reverse/1)
  end

  defp record_event(pid, mod, fun, args) do
    event = %{
      module: mod,
      function: fun,
      args_summary: summarize_args(args),
      timestamp: DateTime.utc_now()
    }

    Agent.update(pid, fn events -> [event | events] end)
  end

  # -- Tracing -----------------------------------------------------------------

  defp setup_traces(collector) do
    handler = build_trace_handler(collector)

    for {mod, fun, arity} <- @traced_mfas do
      try do
        :erlang.trace_pattern({mod, fun, arity}, [{:_, [], [{:return_trace}]}], [:global])
      catch
        _, _ -> :ok
      end
    end

    # Set up a trace on the current process and any spawned processes
    :erlang.trace(:all, true, [:call, {:tracer, spawn_tracer(handler)}])
    :ok
  catch
    _, reason -> {:error, {:trace_setup_failed, reason}}
  end

  defp teardown_traces do
    try do
      :erlang.trace(:all, false, [:call])
    catch
      _, _ -> :ok
    end

    for {mod, fun, arity} <- @traced_mfas do
      try do
        :erlang.trace_pattern({mod, fun, arity}, false, [:global])
      catch
        _, _ -> :ok
      end
    end

    :ok
  end

  defp spawn_tracer(handler) do
    spawn(fn -> tracer_loop(handler) end)
  end

  defp tracer_loop(handler) do
    receive do
      {:trace, _pid, :call, {mod, fun, args}} ->
        handler.(mod, fun, args)
        tracer_loop(handler)

      _ ->
        tracer_loop(handler)
    after
      30_000 -> :ok
    end
  end

  defp build_trace_handler(collector) do
    traced_set =
      @traced_mfas
      |> Enum.map(fn {mod, fun, _arity} -> {mod, fun} end)
      |> MapSet.new()

    fn mod, fun, args ->
      if MapSet.member?(traced_set, {mod, fun}) do
        record_event(collector, mod, fun, args)
      end
    end
  end

  # -- Compilation -------------------------------------------------------------

  defp do_compile(dep_name, project_path) do
    dep_dir = Path.join([project_path, "deps", to_string(dep_name)])

    # Attempt to compile the dep's source files using the Elixir compiler directly.
    # This avoids needing a full Mix project context.
    lib_dir = Path.join(dep_dir, "lib")

    if File.dir?(lib_dir) do
      files =
        Path.wildcard(Path.join(lib_dir, "**/*.ex"))

      if files != [] do
        try do
          Kernel.ParallelCompiler.compile(files)
        rescue
          _ -> {:error, :compilation_failed}
        end
      else
        {:ok, []}
      end
    else
      {:ok, []}
    end
  end

  # -- Helpers -----------------------------------------------------------------

  defp summarize_args(args) when is_list(args) do
    args
    |> Enum.map(&summarize_arg/1)
    |> Enum.join(", ")
  end

  defp summarize_args(args), do: inspect(args, limit: 50, printable_limit: 100)

  defp summarize_arg(arg) when is_binary(arg) do
    if String.length(arg) > 80 do
      String.slice(arg, 0, 80) <> "..."
    else
      inspect(arg)
    end
  end

  defp summarize_arg(arg) when is_atom(arg), do: inspect(arg)
  defp summarize_arg(arg) when is_number(arg), do: inspect(arg)
  defp summarize_arg(arg) when is_list(arg), do: "[#{length(arg)} elements]"
  defp summarize_arg(arg) when is_tuple(arg), do: "tuple/#{tuple_size(arg)}"
  defp summarize_arg(arg) when is_pid(arg), do: inspect(arg)
  defp summarize_arg(_arg), do: "..."
end
