# frozen_string_literal: true

module TokenAuthority
  ##
  # Concern for emitting structured event logs using Rails 8.1 event logging.
  # This module provides consistent event emission for models.
  #
  # All events are automatically namespaced with "token_authority." prefix
  # and enriched with a timestamp.
  #
  # Usage:
  #   include TokenAuthority::EventLogging
  #
  #   # In instance methods:
  #   notify_event("security.session.revoked", session_id: id, user_id: user_id)
  #   debug_event("validation.pkce.started", code_challenge: challenge)
  #
  #   # In class methods:
  #   self.class.notify_event("client.lookup.completed", client_id: id)
  module EventLogging
    extend ActiveSupport::Concern

    included do
      class_attribute :_event_logging_enabled, default: true
    end

    class_methods do
      # Emit a production event using Rails.event.notify
      # @param event_name [String] The event name (will be prefixed with "token_authority.")
      # @param payload [Hash] The event payload
      # @param request_id [String, nil] Optional request ID for traceability
      def notify_event(event_name, request_id: nil, **payload)
        return unless event_logging_enabled?

        full_payload = build_payload(payload, request_id: request_id)
        Rails.event.notify("token_authority.#{event_name}", **full_payload)
      end

      # Emit a debug event using Rails.event.debug
      # @param event_name [String] The event name (will be prefixed with "token_authority.")
      # @param payload [Hash] The event payload
      # @param request_id [String, nil] Optional request ID for traceability
      def debug_event(event_name, request_id: nil, **payload)
        return unless event_logging_enabled?
        return unless debug_events_enabled?

        full_payload = build_payload(payload, request_id: request_id)
        Rails.event.debug("token_authority.#{event_name}", **full_payload)
      end

      private

      def event_logging_enabled?
        _event_logging_enabled && TokenAuthority.config.event_logging_enabled
      end

      def debug_events_enabled?
        TokenAuthority.config.event_logging_debug_events
      end

      def build_payload(payload, request_id: nil)
        base = {timestamp: Time.current.iso8601(6)}
        base[:request_id] = request_id if request_id.present?
        base.merge(payload)
      end
    end

    # Instance method delegates to class methods
    # @param event_name [String] The event name (will be prefixed with "token_authority.")
    # @param payload [Hash] The event payload
    # @param request_id [String, nil] Optional request ID for traceability
    def notify_event(event_name, request_id: nil, **payload)
      self.class.notify_event(event_name, request_id: request_id, **payload)
    end

    # Instance method delegates to class methods
    # @param event_name [String] The event name (will be prefixed with "token_authority.")
    # @param payload [Hash] The event payload
    # @param request_id [String, nil] Optional request ID for traceability
    def debug_event(event_name, request_id: nil, **payload)
      self.class.debug_event(event_name, request_id: request_id, **payload)
    end
  end
end
