# frozen_string_literal: true

module TokenAuthority
  # Provides structured event logging for controller classes.
  #
  # This concern extends event logging for use in controllers by automatically
  # including the request ID in all event payloads. This enables correlation
  # of events across the request lifecycle.
  #
  # Unlike the model EventLogging concern, this version automatically extracts
  # request_id from the controller's request object, eliminating the need to
  # manually pass it.
  #
  # @example Using in a controller
  #   class AuthorizationsController < ApplicationController
  #     include TokenAuthority::ControllerEventLogging
  #
  #     def authorize
  #       notify_event("authorization.request.received",
  #         client_id: params[:client_id],
  #         redirect_uri: params[:redirect_uri])
  #     end
  #   end
  #
  # @since 0.2.0
  module ControllerEventLogging
    extend ActiveSupport::Concern

    included do
      class_attribute :_event_logging_enabled, default: true
    end

    private

    # Emits a production-level event with automatic request ID.
    #
    # The request_id is automatically extracted from the current request
    # for correlation across the request lifecycle.
    #
    # @param event_name [String] the event name (will be prefixed with "token_authority.")
    # @param payload [Hash] additional event data
    #
    # @return [void]
    #
    # @example
    #   notify_event("authorization.request.received",
    #     client_id: params[:client_id],
    #     has_pkce: params[:code_challenge].present?)
    def notify_event(event_name, **payload)
      return unless event_logging_enabled?

      full_payload = build_controller_payload(payload)
      Rails.event.notify("token_authority.#{event_name}", **full_payload)
    end

    # Emits a debug-level event with automatic request ID.
    #
    # Debug events are only emitted when both event_logging_enabled and
    # event_logging_debug_events are true.
    #
    # @param event_name [String] the event name (will be prefixed with "token_authority.")
    # @param payload [Hash] additional event data
    #
    # @return [void]
    def debug_event(event_name, **payload)
      return unless event_logging_enabled?
      return unless debug_events_enabled?

      full_payload = build_controller_payload(payload)
      Rails.event.debug("token_authority.#{event_name}", **full_payload)
    end

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

    # Builds the event payload with timestamp and request_id.
    #
    # @param payload [Hash] the base payload
    # @return [Hash] the enriched payload
    # @api private
    def build_controller_payload(payload)
      base = {timestamp: Time.current.iso8601(6)}
      base[:request_id] = request.request_id if request.respond_to?(:request_id) && request.request_id.present?
      base.merge(payload)
    end
  end
end
