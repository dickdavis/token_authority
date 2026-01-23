# frozen_string_literal: true

module TokenAuthority
  ##
  # Builds the RFC 8414 OAuth 2.0 Authorization Server Metadata response
  class AuthorizationServerMetadata
    def initialize(mount_path:)
      @mount_path = mount_path
    end

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

    def issuer
      TokenAuthority.config.rfc_9068_issuer_url.to_s.chomp("/")
    end

    def scopes_supported
      TokenAuthority.config.scopes&.keys || []
    end

    def service_documentation
      TokenAuthority.config.rfc_8414_service_documentation
    end

    def token_endpoint_auth_methods_supported
      TokenAuthority.config.rfc_7591_allowed_token_endpoint_auth_methods
    end
  end
end
