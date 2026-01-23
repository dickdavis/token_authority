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
      config.rfc_9068_issuer_url.to_s.chomp("/")
    end

    def resource
      config.rfc_9728_resource.presence || issuer
    end

    def authorization_servers
      config.rfc_9728_authorization_servers.presence || [issuer]
    end

    def scopes_supported
      config.rfc_9728_scopes_supported.presence || config.scopes&.keys || []
    end

    def bearer_methods_supported
      config.rfc_9728_bearer_methods_supported
    end

    def jwks_uri
      config.rfc_9728_jwks_uri
    end

    def resource_name
      config.rfc_9728_resource_name
    end

    def resource_documentation
      config.rfc_9728_resource_documentation
    end

    def resource_policy_uri
      config.rfc_9728_resource_policy_uri
    end

    def resource_tos_uri
      config.rfc_9728_resource_tos_uri
    end
  end
end
