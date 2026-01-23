# frozen_string_literal: true

##
# RSpec matchers for testing Rails 8.1 structured event logging.
#
# Usage:
#   expect { get authorize_path, params: { client_id: "123" } }
#     .to emit_event("token_authority.authorization.request.received")
#     .with_payload(client_id: "123")
#
#   expect { post refresh_path, params: { refresh_token: valid_token } }
#     .not_to emit_event("token_authority.security.token.theft_detected")
#
#   expect { complete_oauth_flow }
#     .to emit_events(
#       "token_authority.authorization.request.received",
#       "token_authority.authorization.consent.granted"
#     )

RSpec::Matchers.define :emit_event do |expected_event_name|
  chain :with_payload do |expected_payload|
    @expected_payload = expected_payload
  end

  match do |block|
    @captured_events = capture_events(&block)
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
    @captured_events = capture_events(&block)
    @matching_event = @captured_events.find { |e| e[:name] == expected_event_name }
    @matching_event.nil?
  end

  failure_message do
    if @matching_event.nil?
      "expected event '#{expected_event_name}' to be emitted, but it wasn't\n" \
        "Events emitted: #{format_event_names(@captured_events)}"
    else
      mismatches = payload_mismatches
      "expected event '#{expected_event_name}' to have payload #{@expected_payload.inspect}\n" \
        "but got: #{@matching_event[:payload].slice(*@expected_payload.keys).inspect}\n" \
        "mismatches: #{mismatches.inspect}"
    end
  end

  failure_message_when_negated do
    "expected event '#{expected_event_name}' not to be emitted, but it was\n" \
      "payload: #{@matching_event[:payload].inspect}"
  end

  supports_block_expectations

  def capture_events(&block)
    events = []

    return events unless Rails.respond_to?(:event) && Rails.event.present?

    original_notify = Rails.event.method(:notify)
    original_debug = Rails.event.method(:debug) if Rails.event.respond_to?(:debug)

    allow(Rails.event).to receive(:notify) do |name, **payload|
      events << {name: name, payload: payload}
      original_notify.call(name, **payload)
    end

    if original_debug
      allow(Rails.event).to receive(:debug) do |name, **payload|
        events << {name: name, payload: payload, debug: true}
        original_debug.call(name, **payload)
      end
    end

    block.call
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

RSpec::Matchers.define :emit_events do |*expected_event_names|
  match do |block|
    @captured_events = capture_events(&block)
    @captured_event_names = @captured_events.map { |e| e[:name] }

    @missing_events = expected_event_names - @captured_event_names
    @missing_events.empty?
  end

  failure_message do
    "expected events #{expected_event_names.inspect} to be emitted\n" \
      "missing: #{@missing_events.inspect}\n" \
      "emitted: #{@captured_event_names.inspect}"
  end

  supports_block_expectations

  def capture_events(&block)
    events = []

    return events unless Rails.respond_to?(:event) && Rails.event.present?

    original_notify = Rails.event.method(:notify)
    original_debug = Rails.event.method(:debug) if Rails.event.respond_to?(:debug)

    allow(Rails.event).to receive(:notify) do |name, **payload|
      events << {name: name, payload: payload}
      original_notify.call(name, **payload)
    end

    if original_debug
      allow(Rails.event).to receive(:debug) do |name, **payload|
        events << {name: name, payload: payload, debug: true}
        original_debug.call(name, **payload)
      end
    end

    block.call
    events
  end
end

RSpec::Matchers.define :emit_debug_event do |expected_event_name|
  chain :with_payload do |expected_payload|
    @expected_payload = expected_payload
  end

  match do |block|
    @captured_events = capture_events(&block)
    @matching_event = @captured_events.find { |e| e[:name] == expected_event_name && e[:debug] }

    return false if @matching_event.nil?

    if @expected_payload
      @expected_payload.all? do |key, value|
        @matching_event[:payload][key] == value
      end
    else
      true
    end
  end

  failure_message do
    if @matching_event.nil?
      debug_events = @captured_events.select { |e| e[:debug] }
      "expected debug event '#{expected_event_name}' to be emitted, but it wasn't\n" \
        "debug events emitted: #{format_event_names(debug_events)}"
    else
      "expected debug event '#{expected_event_name}' to have payload #{@expected_payload.inspect}\n" \
        "but got: #{@matching_event[:payload].slice(*@expected_payload.keys).inspect}"
    end
  end

  supports_block_expectations

  def capture_events(&block)
    events = []

    return events unless Rails.respond_to?(:event) && Rails.event.present?

    original_notify = Rails.event.method(:notify)
    original_debug = Rails.event.method(:debug) if Rails.event.respond_to?(:debug)

    allow(Rails.event).to receive(:notify) do |name, **payload|
      events << {name: name, payload: payload}
      original_notify.call(name, **payload)
    end

    if original_debug
      allow(Rails.event).to receive(:debug) do |name, **payload|
        events << {name: name, payload: payload, debug: true}
        original_debug.call(name, **payload)
      end
    end

    block.call
    events
  end

  def format_event_names(events)
    return "(none)" if events.empty?
    events.map { |e| e[:name] }.join(", ")
  end
end
