defmodule VetService.Pipeline.HexPublishConsumer do
  @moduledoc """
  Broadway pipeline that consumes Hex package publish events
  and triggers the scan workflow.

  Uses a DummyProducer by default — in production this will be
  backed by a message queue (e.g., SQS, RabbitMQ, or polling).
  """

  use Broadway

  alias Broadway.Message
  alias VetService.Pipeline.ScanPipeline

  def start_link(opts) do
    producer_module =
      Keyword.get(opts, :producer_module, Broadway.DummyProducer)

    Broadway.start_link(__MODULE__,
      name: __MODULE__,
      producer: [
        module: {producer_module, []},
        concurrency: 1
      ],
      processors: [
        default: [concurrency: 2]
      ],
      batchers: [
        default: [
          batch_size: 10,
          batch_timeout: 1_000,
          concurrency: 1
        ]
      ]
    )
  end

  @impl true
  def handle_message(_processor, %Message{} = message, _context) do
    case ScanPipeline.process_publish_event(message.data) do
      {:ok, result} ->
        Message.put_data(message, result)

      {:error, reason} ->
        Message.failed(message, reason)
    end
  end

  @impl true
  def handle_batch(:default, messages, _batch_info, _context) do
    # Batch projection updates for efficiency
    results = Enum.map(messages, fn msg -> msg.data end)

    Enum.each(results, fn result ->
      VetService.EventHandlers.ProjectionHandler.handle(result)
    end)

    messages
  end
end
