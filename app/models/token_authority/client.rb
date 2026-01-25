# frozen_string_literal: true

module TokenAuthority
  # Represents an OAuth 2.1 client application.
  #
  # Clients can be either public (like mobile or SPA applications) or confidential
  # (like server-side applications). Public clients use PKCE for security, while
  # confidential clients can authenticate using client secrets or JWT assertions.
  #
  # This model handles client registration, authentication, and secure generation
  # of client secrets using HMAC. Secrets are derived from a stored UUID rather
  # than being stored directly, allowing secret rotation via the configuration's
  # secret_key.
  #
  # @example Creating a public client (mobile app)
  #   client = TokenAuthority::Client.create!(
  #     name: "Mobile App",
  #     redirect_uris: ["myapp://oauth/callback"],
  #     token_endpoint_auth_method: "none"
  #   )
  #
  # @example Creating a confidential client (server app)
  #   client = TokenAuthority::Client.create!(
  #     name: "Server App",
  #     redirect_uris: ["https://app.example.com/oauth/callback"],
  #     token_endpoint_auth_method: "client_secret_basic"
  #   )
  #   # Store client.client_secret securely
  #
  # @since 0.2.0
  class Client < ApplicationRecord
    CLIENT_TYPE_ENUM_VALUES = {public: "public", confidential: "confidential"}.freeze
    SUPPORTED_AUTH_METHODS = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt].freeze

    enum :client_type, CLIENT_TYPE_ENUM_VALUES, suffix: true

    validates :name, presence: true, length: {minimum: 3, maximum: 255}
    validates :access_token_duration, numericality: {only_integer: true, greater_than: 0}
    validates :refresh_token_duration, numericality: {only_integer: true, greater_than: 0}
    validates :redirect_uris, presence: true
    validates :token_endpoint_auth_method, inclusion: {in: SUPPORTED_AUTH_METHODS}
    validate :redirect_uris_are_valid_uris
    validate :jwks_required_for_private_key_jwt

    before_validation :set_default_durations, on: :create
    before_validation :set_client_type_from_auth_method, on: :create
    before_validation :set_default_grant_and_response_types, on: :create
    before_create :generate_client_secret_id
    before_create :generate_public_id
    before_create :set_client_id_issued_at
    before_create :set_client_secret_expiration

    # Creates a new authorization grant for this client and the specified user.
    #
    # The grant represents the user's consent to allow this client access.
    # PKCE challenge parameters should be included for public clients.
    #
    # @param user [User] the user granting authorization
    # @param challenge_params [Hash] PKCE parameters (code_challenge, code_challenge_method)
    #
    # @return [TokenAuthority::AuthorizationGrant] the created authorization grant
    #
    # @example
    #   grant = client.new_authorization_grant(
    #     user: current_user,
    #     challenge_params: {
    #       code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    #       code_challenge_method: "S256"
    #     }
    #   )
    def new_authorization_grant(user:, challenge_params: {})
      TokenAuthority::AuthorizationGrant.create(token_authority_client: self, user:, **challenge_params)
    end

    # Creates a new authorization request object for validation.
    #
    # This service object validates all OAuth authorization parameters against
    # the client's configuration and OAuth 2.1 requirements.
    #
    # @param client_id [String] the client identifier
    # @param code_challenge [String] the PKCE code challenge
    # @param code_challenge_method [String] the PKCE method (S256)
    # @param redirect_uri [String] the callback URI
    # @param response_type [String] the response type (code)
    # @param state [String] the state parameter for CSRF protection
    # @param resources [Array<String>] resource indicators (RFC 8707)
    # @param scope [Array<String>] requested scopes
    #
    # @return [TokenAuthority::AuthorizationRequest] the validation object
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

    # Builds a redirect URL with query parameters.
    #
    # Used to redirect back to the client application with authorization codes
    # or error information.
    #
    # @param params [Hash] query parameters to append
    #
    # @return [String] the complete redirect URL
    #
    # @raise [TokenAuthority::InvalidRedirectUrlError] if the URI cannot be parsed
    #
    # @example
    #   url = client.url_for_redirect(params: { code: "abc123", state: "xyz" })
    def url_for_redirect(params:)
      uri = URI(primary_redirect_uri)
      params_for_query = params.collect { |key, value| [key.to_s, value] }
      encoded_params = URI.encode_www_form(params_for_query)
      uri.query = encoded_params
      uri.to_s
    rescue URI::InvalidURIError, ArgumentError, NoMethodError => error
      raise TokenAuthority::InvalidRedirectUrlError, error.message
    end

    # Returns the client secret for confidential clients.
    #
    # The secret is derived from the client_secret_id using HMAC-SHA256 with
    # the application's secret_key. This allows secret rotation by changing
    # the secret_key without modifying the database.
    #
    # @return [String, nil] the client secret, or nil for public clients
    #
    # @note This secret should only be displayed once during client creation
    #   and must be stored securely by the client application.
    def client_secret
      return nil if client_type == "public" || client_secret_id.blank?

      generate_client_secret_for(client_secret_id)
    end

    # Authenticates a client using the provided secret.
    #
    # Uses constant-time comparison to prevent timing attacks that could be
    # used to guess the client secret character by character.
    #
    # @param provided_secret [String] the secret to verify
    #
    # @return [Boolean] true if the secret is valid
    #
    # @example
    #   if client.authenticate_with_secret(params[:client_secret])
    #     # Client authenticated successfully
    #   end
    def authenticate_with_secret(provided_secret)
      return false if client_type == "public" || client_secret_id.blank?
      return false if provided_secret.blank?

      # Use secure comparison to prevent timing attacks
      ActiveSupport::SecurityUtils.secure_compare(
        client_secret,
        provided_secret
      )
    end

    # Checks if a redirect URI is registered for this client.
    #
    # @param uri [String] the redirect URI to check
    #
    # @return [Boolean] true if the URI is registered
    def redirect_uri_registered?(uri)
      redirect_uris&.include?(uri)
    end

    # Returns the primary (first) redirect URI.
    #
    # Used as the default redirect URI when one is not explicitly specified
    # by the client in the authorization request.
    #
    # @return [String, nil] the primary redirect URI
    def primary_redirect_uri
      redirect_uris&.first
    end

    # Indicates whether this is a URL-based client from a client metadata document.
    #
    # Always returns false for registered Client records. URL-based clients are
    # represented by the ClientMetadataDocument class instead.
    #
    # @return [Boolean] false
    #
    # @see TokenAuthority::ClientMetadataDocument#url_based?
    def url_based?
      false
    end

    private

    def redirect_uris_are_valid_uris
      return if redirect_uris.blank?

      redirect_uris.each do |uri|
        parsed_uri = URI.parse(uri)
        unless parsed_uri.is_a?(URI::HTTP) || parsed_uri.is_a?(URI::HTTPS)
          errors.add(:redirect_uris, :invalid_http_scheme)
          break
        end
      rescue URI::InvalidURIError
        errors.add(:redirect_uris, :invalid_uri)
        break
      end
    end

    def jwks_required_for_private_key_jwt
      return unless token_endpoint_auth_method == "private_key_jwt"
      return if jwks.present? || jwks_uri.present?

      errors.add(:base, :jwks_required_for_private_key_jwt)
    end

    def set_client_type_from_auth_method
      return if client_type.present?

      self.client_type = (token_endpoint_auth_method == "none") ? "public" : "confidential"
    end

    def set_default_grant_and_response_types
      self.grant_types ||= ["authorization_code"]
      self.response_types ||= ["code"]
    end

    def generate_client_secret_id
      return if client_type == "public"

      self.client_secret_id = SecureRandom.uuid
    end

    def generate_public_id
      self.public_id = SecureRandom.uuid
    end

    def set_default_durations
      self.access_token_duration ||= TokenAuthority.config.default_access_token_duration
      self.refresh_token_duration ||= TokenAuthority.config.default_refresh_token_duration
    end

    def set_client_id_issued_at
      self.client_id_issued_at = Time.current
    end

    def set_client_secret_expiration
      return if client_type == "public"
      return unless TokenAuthority.config.dcr_client_secret_expiration

      self.client_secret_expires_at = Time.current + TokenAuthority.config.dcr_client_secret_expiration
    end

    def generate_client_secret_for(secret_id)
      OpenSSL::HMAC.hexdigest("SHA256", TokenAuthority.config.secret_key, secret_id)
    end
  end
end
