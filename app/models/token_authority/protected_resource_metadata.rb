# frozen_string_literal: true

module TokenAuthority
  ##
  # Builds the RFC 9728 OAuth 2.0 Protected Resource Metadata response
  class ProtectedResourceMetadata
    def initialize(mount_path:)
      @mount_path = mount_path
    end

    def to_h
      metadata = {
        resource: resource,
        authorization_servers: authorization_servers
      }

      metadata[:scopes_supported] = scopes_supported if scopes_supported.any?
      metadata[:bearer_methods_supported] = bearer_methods_supported if bearer_methods_supported.present?
      metadata[:jwks_uri] = jwks_uri if jwks_uri.present?
      metadata[:resource_name] = resource_name if resource_name.present?
      metadata[:resource_documentation] = resource_documentation if resource_documentation.present?
      metadata[:resource_policy_uri] = resource_policy_uri if resource_policy_uri.present?
      metadata[:resource_tos_uri] = resource_tos_uri if resource_tos_uri.present?

      metadata
    end

    private

    def config
      TokenAuthority.config
    end

    def issuer
      config.issuer_url.to_s.chomp("/")
    end

    def resource
      config.resource_url.presence || issuer
    end

    def authorization_servers
      config.resource_authorization_servers.presence || [issuer]
    end

    def scopes_supported
      config.resource_scopes_supported.presence || config.scopes_supported || []
    end

    def bearer_methods_supported
      config.resource_bearer_methods_supported
    end

    def jwks_uri
      config.resource_jwks_uri
    end

    def resource_name
      config.resource_name
    end

    def resource_documentation
      config.resource_documentation
    end

    def resource_policy_uri
      config.resource_policy_uri
    end

    def resource_tos_uri
      config.resource_tos_uri
    end
  end
end
