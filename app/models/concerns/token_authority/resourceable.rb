# frozen_string_literal: true

module TokenAuthority
  # Provides RFC 8707 resource indicator handling for authorization requests and tokens.
  #
  # Resource indicators allow clients to specify which protected resources (APIs)
  # they want access to. This concern handles validation of resource URIs according
  # to RFC 8707 requirements and checking resources against the configured allowed
  # resource list.
  #
  # Resource URIs must:
  # - Be absolute URIs with http or https scheme
  # - Include a host
  # - Not contain a fragment
  #
  # @example Using in a model
  #   class AuthorizationRequest
  #     include TokenAuthority::Resourceable
  #   end
  #
  #   request.resources = ["https://api.example.com", "https://files.example.com"]
  #   request.resources # => ["https://api.example.com", "https://files.example.com"]
  #
  # @see https://www.rfc-editor.org/rfc/rfc8707.html RFC 8707: Resource Indicators for OAuth 2.0
  # @since 0.2.0
  module Resourceable
    extend ActiveSupport::Concern

    # Returns the resource indicators as an array.
    #
    # @return [Array<String>] the resource URIs
    def resources
      @resources ||= []
    end

    # Sets the resource indicators from an array or array-like value.
    #
    # Nil or empty values result in an empty array.
    #
    # @param value [Array<String>, String, nil] the resource URIs to set
    #
    # @example
    #   obj.resources = ["https://api.example.com"]
    #   obj.resources # => ["https://api.example.com"]
    def resources=(value)
      @resources = Array(value).presence || []
    end

    private

    # Validates that a single resource URI meets RFC 8707 requirements.
    #
    # @param uri [String] the resource URI to validate
    #
    # @return [Boolean] true if the URI is valid
    # @api private
    def valid_resource_uri?(uri)
      return false if uri.blank?

      parsed_uri = URI.parse(uri)

      # Must be absolute URI with http/https scheme
      return false unless parsed_uri.is_a?(URI::HTTP) || parsed_uri.is_a?(URI::HTTPS)

      # Must not have a fragment
      return false if parsed_uri.fragment.present?

      # Must have a host
      return false if parsed_uri.host.blank?

      true
    rescue URI::InvalidURIError
      false
    end

    # Validates that all resource URIs meet RFC 8707 requirements.
    #
    # @return [Boolean] true if all URIs are valid
    # @api private
    def valid_resource_uris?
      resources.all? { |uri| valid_resource_uri?(uri) }
    end

    # Checks if all requested resources are in the allowed resources list.
    #
    # Returns true if resource indicators are not enabled in configuration.
    #
    # @return [Boolean] true if all resources are allowed
    # @api private
    def allowed_resources?
      return true unless TokenAuthority.config.resources_enabled?

      resources.all? { |uri| TokenAuthority.config.resource_registry.key?(uri) }
    end

    # Checks if the current resources are a subset of the granted resources.
    #
    # Used during token refresh to ensure the new token doesn't request
    # access to more resources than the original grant.
    #
    # @param granted [Array<String>, nil] the originally granted resources
    #
    # @return [Boolean] true if resources are a subset of granted resources
    # @api private
    def resources_subset_of?(granted)
      return true if granted.blank? || resources.blank?

      (resources - granted).empty?
    end
  end
end
