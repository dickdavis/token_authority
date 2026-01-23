# frozen_string_literal: true

module TokenAuthority
  ##
  # Concern for emitting structured event logs from controllers.
  # Extends the base EventLogging module with controller-specific features.
  #
  # Automatically adds request_id to all event payloads.
  #
  # Usage:
  #   include TokenAuthority::ControllerEventLogging
  #
  #   def authorize
  #     notify_event("authorization.request.received", client_id: params[:client_id])
  #   end
  module ControllerEventLogging
    extend ActiveSupport::Concern

    included do
      class_attribute :_event_logging_enabled, default: true
    end

    private

    # Emit a production event using Rails.event.notify
    # Automatically includes request_id from the current request
    # @param event_name [String] The event name (will be prefixed with "token_authority.")
    # @param payload [Hash] The event payload
    def notify_event(event_name, **payload)
      return unless event_logging_enabled?

      full_payload = build_controller_payload(payload)
      Rails.event.notify("token_authority.#{event_name}", **full_payload)
    end

    # Emit a debug event using Rails.event.debug
    # Automatically includes request_id from the current request
    # @param event_name [String] The event name (will be prefixed with "token_authority.")
    # @param payload [Hash] The event payload
    def debug_event(event_name, **payload)
      return unless event_logging_enabled?
      return unless debug_events_enabled?

      full_payload = build_controller_payload(payload)
      Rails.event.debug("token_authority.#{event_name}", **full_payload)
    end

    def event_logging_enabled?
      _event_logging_enabled && TokenAuthority.config.event_logging_enabled
    end

    def debug_events_enabled?
      TokenAuthority.config.event_logging_debug_events
    end

    def build_controller_payload(payload)
      base = {timestamp: Time.current.iso8601(6)}
      base[:request_id] = request.request_id if request.respond_to?(:request_id) && request.request_id.present?
      base.merge(payload)
    end
  end
end
