# frozen_string_literal: true

module TokenAuthority
  ##
  # Module for emitting ActiveSupport::Notifications instrumentation events.
  # This module provides automatic timing data that APM tools (New Relic, Datadog, Skylight) auto-capture.
  #
  # All events are namespaced with "token_authority." prefix (e.g., "token_authority.jwt_encode").
  #
  # Usage:
  #   # For modules/classes with class methods (extend):
  #   extend TokenAuthority::Instrumentation
  #
  #   def self.some_method
  #     instrument("event_name", key: value) { ... }
  #   end
  #
  #   # For classes with instance methods (include):
  #   include TokenAuthority::Instrumentation
  #
  #   def some_method
  #     instrument("event_name", key: value) { ... }
  #   end
  module Instrumentation
    NAMESPACE = "token_authority"

    # Core instrumentation method - works as both class and instance method
    # @param event_name [String] The event name (will be prefixed with "token_authority.")
    # @param payload [Hash] The event payload
    # @yield [payload] The block to instrument; payload can be modified inside the block
    # @return The result of the block
    def instrument(event_name, **payload, &block)
      return yield(payload) unless TokenAuthority.config.instrumentation_enabled

      ActiveSupport::Notifications.instrument("#{NAMESPACE}.#{event_name}", payload) do |p|
        yield(p)
      rescue => e
        p[:error] = "#{e.class.name}: #{e.message}"
        raise
      end
    end
  end
end
