# frozen_string_literal: true

##
# RSpec matchers for testing ActiveSupport::Notifications instrumentation events.
#
# Usage:
#   expect { JsonWebToken.encode(payload) }
#     .to instrument("token_authority.jwt_encode")
#     .with_payload(success: true)
#
#   expect { operation_that_fails }
#     .to instrument("token_authority.some_event")
#     .with_payload(success: false)

RSpec::Matchers.define :instrument do |expected_event_name|
  chain :with_payload do |expected_payload|
    @expected_payload = expected_payload
  end

  match do |block|
    @captured_events = capture_instrumentation_events(&block)
    @matching_event = @captured_events.find { |e| e[:name] == expected_event_name }

    return false if @matching_event.nil?

    if @expected_payload
      @expected_payload.all? do |key, value|
        @matching_event[:payload][key] == value
      end
    else
      true
    end
  end

  match_when_negated do |block|
    @captured_events = capture_instrumentation_events(&block)
    @matching_event = @captured_events.find { |e| e[:name] == expected_event_name }
    @matching_event.nil?
  end

  failure_message do
    if @matching_event.nil?
      "expected instrumentation event '#{expected_event_name}' to be emitted, but it wasn't\n" \
        "Events emitted: #{format_event_names(@captured_events)}"
    else
      mismatches = payload_mismatches
      "expected instrumentation event '#{expected_event_name}' to have payload #{@expected_payload.inspect}\n" \
        "but got: #{@matching_event[:payload].slice(*@expected_payload.keys).inspect}\n" \
        "mismatches: #{mismatches.inspect}"
    end
  end

  failure_message_when_negated do
    "expected instrumentation event '#{expected_event_name}' not to be emitted, but it was\n" \
      "payload: #{@matching_event[:payload].inspect}"
  end

  supports_block_expectations

  def capture_instrumentation_events(&block)
    events = []

    callback = ->(name, started, finished, unique_id, payload) {
      events << {
        name: name,
        started: started,
        finished: finished,
        unique_id: unique_id,
        payload: payload,
        duration: (finished - started) * 1000
      }
    }

    # Subscribe to all token_authority.* events
    subscriber = ActiveSupport::Notifications.subscribe(/^token_authority\./, &callback)

    begin
      block.call
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber)
    end

    events
  end

  def format_event_names(events)
    return "(none)" if events.empty?
    events.map { |e| e[:name] }.join(", ")
  end

  def payload_mismatches
    return {} unless @expected_payload && @matching_event

    @expected_payload.each_with_object({}) do |(key, expected_value), mismatches|
      actual_value = @matching_event[:payload][key]
      mismatches[key] = {expected: expected_value, got: actual_value} if actual_value != expected_value
    end
  end
end
