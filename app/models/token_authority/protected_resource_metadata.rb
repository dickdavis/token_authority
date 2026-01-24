# frozen_string_literal: true

module TokenAuthority
  ##
  # Assembles RFC 9728 Protected Resource Metadata responses for OAuth clients.
  #
  # This class transforms configured resource metadata into standardized JSON responses
  # that clients use to discover how to interact with protected resources. The metadata
  # includes supported scopes, bearer token methods, and links to authorization servers.
  #
  # The lookup strategy supports multi-tenant deployments: the resource_key parameter
  # (typically extracted from the request subdomain) determines which configuration
  # to use. If no subdomain-specific configuration exists, falls back to the default
  # protected_resource configuration. This allows a single authorization server to
  # describe multiple protected resources at different subdomains.
  #
  # @example Single resource (no subdomain routing)
  #   metadata = ProtectedResourceMetadata.new(resource: nil)
  #   metadata.to_h
  #   # => { resource: "https://api.example.com", authorization_servers: [...], ... }
  #
  # @example Multi-tenant with subdomain-specific config
  #   metadata = ProtectedResourceMetadata.new(resource: "api")
  #   metadata.to_h
  #   # => Returns config for "api" subdomain from protected_resources hash
  #
  # @see https://www.rfc-editor.org/rfc/rfc9728.html RFC 9728 OAuth 2.0 Protected Resource Metadata
  # @since 0.3.0
  class ProtectedResourceMetadata
    # RFC 9728 defines these standard metadata fields for protected resources.
    # This constant serves as documentation of the complete metadata schema and
    # ensures field ordering matches the RFC for consistency.
    ATTRIBUTES = %i[
      resource
      authorization_servers
      scopes_supported
      bearer_methods_supported
      resource_name
      resource_documentation
      resource_policy_uri
      resource_tos_uri
      jwks_uri
    ].freeze

    # @return [String, nil] the lookup key used to find configuration (typically subdomain)
    attr_reader :resource_key

    # Initializes metadata builder for a specific resource.
    #
    # The resource parameter acts as a lookup key into the configuration system.
    # In typical deployments, this is the request subdomain (e.g., "api", "mcp").
    # When nil or blank, uses the default protected_resource configuration.
    #
    # @param resource [String, nil] the configuration key to look up
    def initialize(resource:)
      @resource_key = resource
    end

    # Generates the RFC 9728 metadata response as a hash.
    #
    # Returns only the fields that are configured; optional fields with nil or blank
    # values are omitted to reduce response size and comply with RFC requirements.
    # The authorization_servers field defaults to the OAuth issuer URL if not explicitly
    # configured, ensuring clients always know where to obtain tokens.
    #
    # @return [Hash{Symbol => Object}] metadata hash with snake_case keys
    # @raise [ResourceNotConfiguredError] if no configuration exists for the resource_key
    def to_h
      {
        resource: resource,
        authorization_servers: authorization_servers,
        scopes_supported: scopes_supported,
        bearer_methods_supported: bearer_methods_supported,
        jwks_uri: jwks_uri,
        resource_name: resource_name,
        resource_documentation: resource_documentation,
        resource_policy_uri: resource_policy_uri,
        resource_tos_uri: resource_tos_uri
      }.compact_blank
    end

    private

    # Retrieves the configuration hash for this resource.
    #
    # Delegates to Configuration#protected_resource_for which implements the
    # fallback strategy (subdomain-specific -> default -> nil). Memoizes the
    # result since configuration doesn't change during a request.
    #
    # @return [Hash] the resource configuration hash
    # @raise [ResourceNotConfiguredError] if no config exists for the resource key
    def resource_config
      @resource_config ||= TokenAuthority.config.protected_resource_for(resource_key) ||
        raise(ResourceNotConfiguredError)
    end

    # The URI identifying this protected resource.
    # This is the only required field in RFC 9728 metadata.
    #
    # @return [String] resource identifier URI
    def resource
      resource_config[:resource]
    end

    # Array of authorization server URLs that can issue tokens for this resource.
    #
    # Defaults to the configured issuer URL if not explicitly set, which is correct
    # for the common case where the authorization server and protected resource
    # share the same deployment. Multi-AS scenarios can override this.
    #
    # @return [Array<String>] authorization server URLs
    def authorization_servers
      resource_config[:authorization_servers].presence || [issuer]
    end

    def scopes_supported
      resource_config[:scopes_supported]
    end

    def bearer_methods_supported
      resource_config[:bearer_methods_supported]
    end

    def jwks_uri
      resource_config[:jwks_uri]
    end

    def resource_name
      resource_config[:resource_name]
    end

    def resource_documentation
      resource_config[:resource_documentation]
    end

    def resource_policy_uri
      resource_config[:resource_policy_uri]
    end

    def resource_tos_uri
      resource_config[:resource_tos_uri]
    end

    # The authorization server issuer URL, used as a default for authorization_servers.
    #
    # Strips trailing slash for consistency with OAuth discovery URL formats, which
    # typically omit trailing slashes in issuer identifiers.
    #
    # @return [String] issuer URL without trailing slash
    def issuer
      TokenAuthority.config.rfc_9068_issuer_url.to_s.chomp("/")
    end
  end
end
