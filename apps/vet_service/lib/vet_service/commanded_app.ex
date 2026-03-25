defmodule VetService.CommandedApp do
  @moduledoc """
  Commanded application for VetService event sourcing.

  This module defines the Commanded application that wires together
  the router, aggregates, and event store.
  """

  use Commanded.Application, otp_app: :vet_service

  router(VetService.Router)
end
