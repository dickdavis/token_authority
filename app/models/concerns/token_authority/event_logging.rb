# frozen_string_literal: true

module TokenAuthority
  # Provides structured event logging for model classes.
  #
  # This concern integrates with Rails 8.1+ event logging (Rails.event) to emit
  # structured, machine-readable events for security auditing, monitoring, and debugging.
  # All events are automatically namespaced and timestamped.
  #
  # Two event levels are supported:
  # - Production events (notify_event): Always emitted when event_logging_enabled is true
  # - Debug events (debug_event): Only emitted when both event_logging_enabled and
  #   event_logging_debug_events are true
  #
  # Events can be consumed by Rails event subscribers for logging, metrics, or
  # integration with external monitoring systems.
  #
  # @example Using in a model
  #   class Session < ApplicationRecord
  #     include TokenAuthority::EventLogging
  #
  #     def revoke
  #       notify_event("security.session.revoked",
  #         session_id: id,
  #         client_id: client.public_id,
  #         reason: "user_logout")
  #     end
  #   end
  #
  # @example Using debug events
  #   debug_event("validation.pkce.started",
  #     code_challenge: challenge,
  #     challenge_method: "S256")
  #
  # @since 0.2.0
  module EventLogging
    extend ActiveSupport::Concern

    included do
      class_attribute :_event_logging_enabled, default: true
    end

    class_methods do
      # Emits a production-level event.
      #
      # Events are namespaced with "token_authority." and include a timestamp.
      # Only emitted when event logging is enabled in configuration.
      #
      # @param event_name [String] the event name (will be prefixed)
      # @param request_id [String, nil] optional request ID for correlation
      # @param payload [Hash] additional event data
      #
      # @return [void]
      #
      # @example
      #   notify_event("client.lookup.completed",
      #     client_id: "abc123",
      #     lookup_duration_ms: 42)
      def notify_event(event_name, request_id: nil, **payload)
        return unless event_logging_enabled?

        full_payload = build_payload(payload, request_id: request_id)
        Rails.event.notify("token_authority.#{event_name}", **full_payload)
      end

      # Emits a debug-level event.
      #
      # Debug events are only emitted when both event_logging_enabled and
      # event_logging_debug_events are true in configuration. Use for verbose
      # logging that aids in troubleshooting but would be too noisy in production.
      #
      # @param event_name [String] the event name (will be prefixed)
      # @param request_id [String, nil] optional request ID for correlation
      # @param payload [Hash] additional event data
      #
      # @return [void]
      #
      # @example
      #   debug_event("validation.pkce.challenge_computed",
      #     code_verifier_length: 128,
      #     challenge_method: "S256")
      def debug_event(event_name, request_id: nil, **payload)
        return unless event_logging_enabled?
        return unless debug_events_enabled?

        full_payload = build_payload(payload, request_id: request_id)
        Rails.event.debug("token_authority.#{event_name}", **full_payload)
      end

      private

      # Checks if event logging is enabled.
      # @return [Boolean]
      # @api private
      def event_logging_enabled?
        _event_logging_enabled && TokenAuthority.config.event_logging_enabled
      end

      # Checks if debug events are enabled.
      # @return [Boolean]
      # @api private
      def debug_events_enabled?
        TokenAuthority.config.event_logging_debug_events
      end

      # Builds the complete event payload with timestamp and optional request_id.
      # @param payload [Hash] the base payload
      # @param request_id [String, nil] optional request ID
      # @return [Hash] the enriched payload
      # @api private
      def build_payload(payload, request_id: nil)
        base = {timestamp: Time.current.iso8601(6)}
        base[:request_id] = request_id if request_id.present?
        base.merge(payload)
      end
    end

    # Emits a production-level event from instance methods.
    #
    # Delegates to the class method. See class method documentation for details.
    #
    # @param event_name [String] the event name (will be prefixed)
    # @param request_id [String, nil] optional request ID for correlation
    # @param payload [Hash] additional event data
    #
    # @return [void]
    def notify_event(event_name, request_id: nil, **payload)
      self.class.notify_event(event_name, request_id: request_id, **payload)
    end

    # Emits a debug-level event from instance methods.
    #
    # Delegates to the class method. See class method documentation for details.
    #
    # @param event_name [String] the event name (will be prefixed)
    # @param request_id [String, nil] optional request ID for correlation
    # @param payload [Hash] additional event data
    #
    # @return [void]
    def debug_event(event_name, request_id: nil, **payload)
      self.class.debug_event(event_name, request_id: request_id, **payload)
    end
  end
end
