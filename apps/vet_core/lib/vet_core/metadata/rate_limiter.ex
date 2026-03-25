defmodule VetCore.Metadata.RateLimiter do
  @moduledoc false
  use GenServer

  @interval_ms 100

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def throttle(fun) when is_function(fun, 0) do
    GenServer.call(__MODULE__, {:throttle, fun}, :infinity)
  end

  @impl true
  def init(_opts) do
    {:ok, %{last_call: 0}}
  end

  @impl true
  def handle_call({:throttle, fun}, _from, state) do
    now = System.monotonic_time(:millisecond)
    elapsed = now - state.last_call
    wait = max(0, @interval_ms - elapsed)

    if wait > 0, do: Process.sleep(wait)

    result = fun.()
    {:reply, result, %{state | last_call: System.monotonic_time(:millisecond)}}
  end
end
