# frozen_string_literal: true

module TokenAuthority
  ##
  # Represents a client identified by a URL-based client_id (Client Metadata Document spec).
  # Implements the same interface as Client for use in OAuth flows.
  class ClientMetadataDocument
    attr_reader :metadata

    def initialize(metadata)
      @metadata = metadata.with_indifferent_access
    end

    # The client_id is the URL itself
    def public_id
      metadata[:client_id]
    end

    # URL-based clients are always public (per spec)
    def client_type
      "public"
    end

    def public_client_type?
      true
    end

    def confidential_client_type?
      false
    end

    def name
      metadata[:client_name] || metadata[:client_id]
    end

    def redirect_uris
      metadata[:redirect_uris] || []
    end

    def redirect_uri_registered?(uri)
      redirect_uris.include?(uri)
    end

    def primary_redirect_uri
      redirect_uris.first
    end

    # URL-based clients use default token durations from config
    def access_token_duration
      TokenAuthority.config.rfc_9068_default_access_token_duration
    end

    def refresh_token_duration
      TokenAuthority.config.rfc_9068_default_refresh_token_duration
    end

    # URL-based clients cannot have secrets
    def client_secret
      nil
    end

    def client_secret_id
      nil
    end

    def authenticate_with_secret(_provided_secret)
      false
    end

    # URL-based clients always use "none" for token endpoint auth
    def token_endpoint_auth_method
      "none"
    end

    def grant_types
      metadata[:grant_types] || ["authorization_code"]
    end

    def response_types
      metadata[:response_types] || ["code"]
    end

    def scope
      metadata[:scope]
    end

    # Human-readable metadata
    def client_uri
      metadata[:client_uri]
    end

    def logo_uri
      metadata[:logo_uri]
    end

    def tos_uri
      metadata[:tos_uri]
    end

    def policy_uri
      metadata[:policy_uri]
    end

    def contacts
      metadata[:contacts]
    end

    # Technical metadata
    def jwks_uri
      metadata[:jwks_uri]
    end

    def jwks
      metadata[:jwks]
    end

    def software_id
      metadata[:software_id]
    end

    def software_version
      metadata[:software_version]
    end

    # Creates a new authorization grant for this URL-based client
    def new_authorization_grant(user:, challenge_params: {})
      TokenAuthority::AuthorizationGrant.create(
        client_id_url: public_id,
        user:,
        **challenge_params
      )
    end

    # Creates a new authorization request for this URL-based client
    def new_authorization_request(client_id:, code_challenge:, code_challenge_method:, redirect_uri:, response_type:, state:, resources: [], scope: [])
      TokenAuthority::AuthorizationRequest.new(
        token_authority_client: self,
        client_id:,
        state:,
        code_challenge:,
        code_challenge_method:,
        redirect_uri:,
        response_type:,
        resources:,
        scope:
      )
    end

    def url_for_redirect(params:)
      uri = URI(primary_redirect_uri)
      params_for_query = params.collect { |key, value| [key.to_s, value] }
      encoded_params = URI.encode_www_form(params_for_query)
      uri.query = encoded_params
      uri.to_s
    rescue URI::InvalidURIError, ArgumentError, NoMethodError => error
      raise TokenAuthority::InvalidRedirectUrlError, error.message
    end

    # Check if this is a URL-based client (always true for this class)
    def url_based?
      true
    end
  end
end
