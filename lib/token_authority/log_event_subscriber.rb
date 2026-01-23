# frozen_string_literal: true

module TokenAuthority
  ##
  # A Rails.event subscriber that logs TokenAuthority events to Rails.logger.
  #
  # This subscriber only processes events with the "token_authority." prefix,
  # ignoring all other Rails events.
  #
  # Usage:
  #   # Automatically enabled via configuration:
  #   TokenAuthority.configure do |config|
  #     config.event_logging_rails_logger = true
  #   end
  #
  #   # Or manually subscribe:
  #   Rails.event.subscribe(TokenAuthority::LogEventSubscriber.new)
  #
  class LogEventSubscriber
    # @param event [Hash] The event hash from Rails.event
    #   - :name [String] Event name (e.g., "token_authority.authorization.request.received")
    #   - :payload [Hash] Event-specific data
    #   - :context [Hash] Request-level context (request_id, user_id, etc.)
    #   - :tags [Hash] Domain tags
    #   - :timestamp [Integer] Nanosecond timestamp
    #   - :source_location [Hash] File, line, and method info
    def emit(event)
      name = event[:name]

      # Only log token_authority events
      return unless name.start_with?("token_authority.")

      payload = event[:payload] || {}
      context = event[:context] || {}

      # Format payload as key=value pairs
      payload_str = payload.map { |k, v| "#{k}=#{v.inspect}" }.join(" ")
      context_str = context.any? ? " context=#{context.inspect}" : ""

      Rails.logger.info("[TokenAuthority] #{name} #{payload_str}#{context_str}")
    end
  end
end
