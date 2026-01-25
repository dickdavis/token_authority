# frozen_string_literal: true

module TokenAuthority
  module AuthorizationGrantsHelper
    # Returns a human-friendly display name for a resource URI.
    # Looks up the URI in the resource registry derived from protected resources.
    # Falls back to the URI itself if no mapping is configured.
    #
    # @param resource_uri [String] The resource URI
    # @return [String] The display name or the URI if no mapping exists
    def resource_display_name(resource_uri)
      TokenAuthority.config.resource_registry[resource_uri] || resource_uri
    end

    # Returns a human-friendly display name for a scope.
    # Looks up the scope in the configured scopes mapping.
    # Falls back to the scope itself if no mapping is configured.
    #
    # @param scope [String] The scope string
    # @return [String] The display name or the scope if no mapping exists
    def scope_display_name(scope)
      scopes = TokenAuthority.config.scopes || {}
      scopes[scope] || scope
    end
  end
end
