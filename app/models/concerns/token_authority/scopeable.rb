# frozen_string_literal: true

module TokenAuthority
  ##
  # Provides scope handling behavior for models that have scopes.
  # Handles parsing space-delimited scope strings, serialization, and validation helpers.
  module Scopeable
    extend ActiveSupport::Concern

    # Valid scope token per RFC 6749 Section 3.3
    # Must not contain whitespace, double quotes, or backslashes
    VALID_SCOPE_TOKEN = /\A[\x21\x23-\x5B\x5D-\x7E]+\z/

    def scope=(value)
      @scope = case value
      when String then value.split(/\s+/).reject(&:blank?)
      when Array then value
      else []
      end
    end

    def scope_as_string
      Array(scope).join(" ")
    end

    private

    def valid_scope_tokens?
      Array(scope).all? { |s| VALID_SCOPE_TOKEN.match?(s) }
    end

    def allowed_scopes?
      return true unless TokenAuthority.config.scopes_enabled?
      Array(scope).all? { |s| TokenAuthority.config.scopes.key?(s) }
    end

    def scopes_subset_of?(granted)
      return true if granted.blank? || scope.blank?
      (Array(scope) - Array(granted)).empty?
    end
  end
end
