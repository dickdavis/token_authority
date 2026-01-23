# frozen_string_literal: true

module TokenAuthority
  module AuthorizationGrantsHelper
    # Returns a human-friendly display name for a resource URI.
    # Looks up the URI in the configured rfc_8707_resources mapping.
    # Falls back to the URI itself if no mapping is configured.
    #
    # @param resource_uri [String] The resource URI
    # @return [String] The display name or the URI if no mapping exists
    def resource_display_name(resource_uri)
      resources = TokenAuthority.config.rfc_8707_resources || {}
      resources[resource_uri] || resource_uri
    end
  end
end
