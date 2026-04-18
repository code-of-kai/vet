defmodule VetReporter do
  @moduledoc false

  def report(scan_report, format \\ :terminal)

  def report(scan_report, :terminal) do
    VetReporter.Terminal.render(scan_report)
  end

  def report(scan_report, :json) do
    VetReporter.Json.render(scan_report)
  end

  def report(scan_report, :sarif) do
    VetReporter.Sarif.render(scan_report)
  end

  def report(scan_report, :diagnostics) do
    VetReporter.Diagnostics.render(scan_report)
  end
end
