# frozen_string_literal: true

module TokenAuthority
  # Builds OAuth 2.0 Authorization Server Metadata per RFC 8414.
  #
  # This class generates the metadata document that clients use to discover
  # the authorization server's capabilities and endpoint locations. The metadata
  # is typically served at /.well-known/oauth-authorization-server.
  #
  # The metadata includes:
  # - Endpoint URLs (authorization, token, revocation, registration)
  # - Supported grant types and response types
  # - Supported token endpoint authentication methods
  # - PKCE code challenge methods
  # - Optional scopes and service documentation
  #
  # @example Building metadata
  #   metadata = AuthorizationServerMetadata.new(mount_path: "/oauth")
  #   metadata.to_h
  #   # => {
  #   #   issuer: "https://example.com",
  #   #   authorization_endpoint: "https://example.com/oauth/authorize",
  #   #   ...
  #   # }
  #
  # @see https://www.rfc-editor.org/rfc/rfc8414.html RFC 8414: OAuth 2.0 Authorization Server Metadata
  # @since 0.2.0
  class AuthorizationServerMetadata
    # Creates a new metadata builder.
    #
    # @param mount_path [String] the path where the OAuth engine is mounted
    #   (e.g., "/oauth")
    def initialize(mount_path:)
      @mount_path = mount_path
    end

    # Converts the metadata to a hash for JSON serialization.
    #
    # Builds the complete metadata document including all required and optional
    # fields based on the current configuration. The registration_endpoint is
    # only included when dynamic client registration is enabled.
    #
    # @return [Hash] the authorization server metadata
    #
    # @example
    #   metadata = AuthorizationServerMetadata.new(mount_path: "/oauth")
    #   json = metadata.to_h.to_json
    def to_h
      metadata = {
        issuer: issuer,
        authorization_endpoint: "#{issuer}#{@mount_path}/authorize",
        token_endpoint: "#{issuer}#{@mount_path}/token",
        revocation_endpoint: "#{issuer}#{@mount_path}/revoke",
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported: token_endpoint_auth_methods_supported,
        code_challenge_methods_supported: ["S256"]
      }

      metadata[:scopes_supported] = scopes_supported if scopes_supported.any?
      metadata[:service_documentation] = service_documentation if service_documentation.present?

      # RFC 7591 Dynamic Client Registration
      if TokenAuthority.config.rfc_7591_enabled
        metadata[:registration_endpoint] = "#{issuer}#{@mount_path}/register"
      end

      metadata
    end

    private

    # Returns the issuer URL from configuration with trailing slashes removed.
    # @return [String]
    # @api private
    def issuer
      TokenAuthority.config.rfc_9068_issuer_url.to_s.chomp("/")
    end

    # Returns the list of supported scopes from configuration.
    # @return [Array<String>]
    # @api private
    def scopes_supported
      TokenAuthority.config.scopes&.keys || []
    end

    # Returns the service documentation URL from configuration.
    # @return [String, nil]
    # @api private
    def service_documentation
      TokenAuthority.config.rfc_8414_service_documentation
    end

    # Returns the supported token endpoint authentication methods.
    # @return [Array<String>]
    # @api private
    def token_endpoint_auth_methods_supported
      TokenAuthority.config.rfc_7591_allowed_token_endpoint_auth_methods
    end
  end
end
