# frozen_string_literal: true

module TokenAuthority
  # Provides OAuth scope handling for authorization requests and tokens.
  #
  # This concern handles parsing space-delimited scope strings per OAuth 2.1,
  # validation of scope tokens per RFC 6749, and checking scopes against the
  # configured allowed scopes.
  #
  # Scopes are stored internally as arrays but can be set from either strings
  # or arrays. The scope setter automatically splits space-delimited strings
  # into individual scope tokens.
  #
  # @example Using in a model
  #   class AuthorizationRequest
  #     include TokenAuthority::Scopeable
  #   end
  #
  #   request.scope = "read write admin"
  #   request.scope # => ["read", "write", "admin"]
  #   request.scope_as_string # => "read write admin"
  #
  # @since 0.2.0
  module Scopeable
    extend ActiveSupport::Concern

    # Regular expression for valid scope tokens per RFC 6749 Section 3.3.
    # Scope tokens must not contain whitespace, double quotes, or backslashes.
    # Allowed characters are printable ASCII excluding space, double-quote, and backslash.
    VALID_SCOPE_TOKEN = /\A[\x21\x23-\x5B\x5D-\x7E]+\z/

    # Returns the scopes as an array.
    #
    # @return [Array<String>] the scope tokens
    def scope
      @scope ||= []
    end

    # Sets the scopes from a string or array.
    #
    # String values are split on whitespace into individual tokens.
    # Array values are used directly. Other values result in an empty array.
    #
    # @param value [String, Array<String>, nil] the scopes to set
    #
    # @example Setting from a string
    #   obj.scope = "read write"
    #   obj.scope # => ["read", "write"]
    #
    # @example Setting from an array
    #   obj.scope = ["read", "write"]
    #   obj.scope # => ["read", "write"]
    def scope=(value)
      @scope = case value
      when String then value.split(/\s+/).reject(&:blank?)
      when Array then value
      else []
      end
    end

    # Returns the scopes as a space-delimited string.
    #
    # This format is used in OAuth responses and JWT scope claims.
    #
    # @return [String] space-delimited scope string
    def scope_as_string
      scope.join(" ")
    end

    private

    # Validates that all scope tokens match the RFC 6749 format.
    #
    # @return [Boolean] true if all tokens are valid
    # @api private
    def valid_scope_tokens?
      scope.all? { |s| VALID_SCOPE_TOKEN.match?(s) }
    end

    # Checks if all requested scopes are in the allowed scopes list.
    #
    # Returns true if scopes are not enabled in configuration.
    #
    # @return [Boolean] true if all scopes are allowed
    # @api private
    def allowed_scopes?
      return true unless TokenAuthority.config.scopes_enabled?
      scope.all? { |s| TokenAuthority.config.scopes.key?(s) }
    end

    # Checks if the current scopes are a subset of the granted scopes.
    #
    # Used during token refresh to ensure the new token doesn't request
    # more privileges than the original grant.
    #
    # @param granted [Array<String>, nil] the originally granted scopes
    #
    # @return [Boolean] true if scopes are a subset of granted scopes
    # @api private
    def scopes_subset_of?(granted)
      return true if granted.blank? || scope.blank?
      (scope - Array(granted)).empty?
    end
  end
end
