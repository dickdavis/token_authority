# frozen_string_literal: true

module TokenAuthority
  # Provides instrumentation capabilities using ActiveSupport::Notifications.
  #
  # This module emits performance and timing data that APM tools (New Relic, Datadog,
  # Skylight) can automatically capture. It can be included in classes or extended
  # in modules to add instrumentation to methods.
  #
  # All events are automatically namespaced with "token_authority." prefix to avoid
  # conflicts with other instrumentation in the application.
  #
  # @example Using in a module with class methods
  #   module MyModule
  #     extend TokenAuthority::Instrumentation
  #
  #     def self.process_data
  #       instrument("process_data", record_count: 100) do |payload|
  #         # Do work here
  #         # Can add additional payload data: payload[:rows_processed] = 42
  #       end
  #     end
  #   end
  #
  # @example Using in a class with instance methods
  #   class MyClass
  #     include TokenAuthority::Instrumentation
  #
  #     def process_record
  #       instrument("process_record") do
  #         # Do work here
  #       end
  #     end
  #   end
  #
  # @since 0.2.0
  module Instrumentation
    # The namespace prefix for all instrumentation events.
    # @return [String]
    NAMESPACE = "token_authority"

    # Wraps a block of code with instrumentation timing and error tracking.
    #
    # If instrumentation is disabled via configuration, the block is executed
    # without emitting notifications. Errors are captured in the payload before
    # being re-raised.
    #
    # @param event_name [String] the event name (will be prefixed with "token_authority.")
    # @param payload [Hash] initial payload data for the event
    #
    # @yield [payload] the block to instrument; the payload can be modified within the block
    # @yieldparam payload [Hash] the mutable event payload
    #
    # @return the result of the yielded block
    #
    # @raise re-raises any exception from the block after capturing it in the payload
    #
    # @example Basic usage
    #   instrument("database.query", table: "users") do |payload|
    #     result = run_query
    #     payload[:rows] = result.count
    #     result
    #   end
    #
    # @example Error handling
    #   instrument("risky_operation") do
    #     raise "Something went wrong"  # Error is logged to payload before re-raising
    #   end
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
