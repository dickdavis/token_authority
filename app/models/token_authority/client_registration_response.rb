# frozen_string_literal: true

module TokenAuthority
  ##
  # Value object for building RFC 7591-compliant client registration response
  class ClientRegistrationResponse
    attr_reader :client

    def initialize(client:)
      @client = client
    end

    def to_h
      response = {
        client_id: client.public_id,
        client_id_issued_at: client.client_id_issued_at.to_i
      }

      # Only include client_secret for confidential clients
      if client.confidential_client_type?
        response[:client_secret] = client.client_secret
        response[:client_secret_expires_at] = client.client_secret_expires_at&.to_i || 0
      end

      # Echo back all registered metadata
      response.merge!(metadata)

      response.compact
    end

    def to_json(*)
      to_h.to_json
    end

    private

    def metadata
      {
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        grant_types: client.grant_types,
        response_types: client.response_types,
        client_name: client.name,
        client_uri: client.client_uri,
        logo_uri: client.logo_uri,
        tos_uri: client.tos_uri,
        policy_uri: client.policy_uri,
        contacts: client.contacts,
        scope: client.scope,
        jwks_uri: client.jwks_uri,
        jwks: client.jwks,
        software_id: client.software_id,
        software_version: client.software_version
        # Note: software_statement is intentionally NOT echoed per RFC 7591
      }
    end
  end
end
