# frozen_string_literal: true

module TokenAuthority
  ##
  # Subscribes to TokenAuthority instrumentation events and logs them to Rails.logger.
  #
  # Events are logged at info level with timing information. This is useful for
  # development debugging and performance analysis.
  #
  # Usage:
  #   # Automatically enabled via configuration:
  #   TokenAuthority.configure do |config|
  #     config.instrumentation_enabled = true
  #   end
  #
  #   # Or manually subscribe:
  #   TokenAuthority::InstrumentationLogSubscriber.subscribe!
  #
  class InstrumentationLogSubscriber
    class << self
      def subscribe!
        ActiveSupport::Notifications.subscribe(/^token_authority\./) do |name, start, finish, id, payload|
          duration_ms = (finish - start) * 1000
          log_event(name, duration_ms, payload)
        end
      end

      private

      def log_event(name, duration_ms, payload)
        payload_str = payload.except(:exception).map { |k, v| "#{k}=#{v.inspect}" }.join(" ")
        Rails.logger.info { "[TokenAuthority::Instrumentation] #{name} (#{duration_ms.round(2)}ms) #{payload_str}" }
      end
    end
  end
end
