# frozen_string_literal: true

module TokenAuthority
  # Subscribes to TokenAuthority instrumentation events and logs them to Rails logger.
  #
  # This subscriber captures all instrumentation events emitted by the TokenAuthority
  # engine and writes them to the Rails log with timing information. This is valuable
  # for development debugging and performance analysis.
  #
  # The subscriber is automatically enabled when `instrumentation_enabled` is true
  # in the configuration. It can also be manually enabled for testing or debugging.
  #
  # Events are logged at INFO level with the format:
  #   [TokenAuthority::Instrumentation] event_name (duration_ms) key1=value1 key2=value2
  #
  # @example Automatic subscription via configuration
  #   TokenAuthority.configure do |config|
  #     config.instrumentation_enabled = true
  #   end
  #
  # @example Manual subscription
  #   TokenAuthority::InstrumentationLogSubscriber.subscribe!
  #
  # @since 0.2.0
  class InstrumentationLogSubscriber
    class << self
      # Subscribes to all TokenAuthority instrumentation events.
      #
      # Creates a wildcard subscription for all events matching the pattern
      # /^token_authority\./. Each event is logged with its name, duration,
      # and payload data.
      #
      # @return [ActiveSupport::Notifications::Subscription] the subscription object
      #
      # @note This method should only be called once during application initialization
      #   to avoid duplicate log entries.
      def subscribe!
        ActiveSupport::Notifications.subscribe(/^token_authority\./) do |name, start, finish, id, payload|
          duration_ms = (finish - start) * 1000
          log_event(name, duration_ms, payload)
        end
      end

      private

      # Formats and logs an instrumentation event.
      #
      # Exceptions are excluded from the payload output to avoid cluttering logs,
      # as they're typically logged separately by Rails' exception handling.
      #
      # @param name [String] the full event name (e.g., "token_authority.jwt.encode")
      # @param duration_ms [Float] the event duration in milliseconds
      # @param payload [Hash] the event payload data
      #
      # @return [void]
      def log_event(name, duration_ms, payload)
        payload_str = payload.except(:exception).map { |k, v| "#{k}=#{v.inspect}" }.join(" ")
        Rails.logger.info { "[TokenAuthority::Instrumentation] #{name} (#{duration_ms.round(2)}ms) #{payload_str}" }
      end
    end
  end
end
