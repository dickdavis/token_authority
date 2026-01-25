# frozen_string_literal: true

module TokenAuthority
  # Validates OAuth 2.1 authorization requests.
  #
  # This service object validates all parameters of an authorization request
  # according to OAuth 2.1 specifications, including PKCE requirements, redirect
  # URI validation, resource indicators (RFC 8707), and scope validation.
  #
  # It enforces different validation rules for public vs confidential clients:
  # - Public clients MUST include PKCE parameters
  # - Confidential clients MAY include PKCE parameters
  # - Public clients MUST include redirect_uri
  # - Confidential clients MAY omit redirect_uri if only one is registered
  #
  # After validation, the request can be serialized to an internal state token
  # (JWT) for storage during the consent flow, then deserialized when processing
  # the user's approval or denial.
  #
  # @example Validating an authorization request
  #   request = AuthorizationRequest.new(
  #     token_authority_client: client,
  #     client_id: "abc123",
  #     redirect_uri: "https://app.example.com/callback",
  #     response_type: "code",
  #     state: "xyz",
  #     code_challenge: "E9Melhoa...",
  #     code_challenge_method: "S256"
  #   )
  #   if request.valid?
  #     # Process authorization
  #   end
  #
  # @since 0.2.0
  class AuthorizationRequest
    include ActiveModel::Model
    include ActiveModel::Validations
    include TokenAuthority::Resourceable
    include TokenAuthority::Scopeable

    # Valid PKCE code challenge methods per OAuth 2.1.
    # Only S256 (SHA-256) is supported; plain is not allowed.
    VALID_CODE_CHALLENGE_METHODS = ["S256"].freeze

    # Valid response types. Currently only "code" is supported.
    VALID_RESPONSE_TYPES = ["code"].freeze

    # @!attribute [rw] token_authority_client
    #   The client making the authorization request.
    #   @return [TokenAuthority::Client, TokenAuthority::ClientMetadataDocument]
    attr_accessor :token_authority_client

    # @!attribute [rw] client_id
    #   The client identifier.
    #   @return [String]
    attr_accessor :client_id

    # @!attribute [rw] code_challenge
    #   The PKCE code challenge.
    #   @return [String, nil]
    attr_accessor :code_challenge

    # @!attribute [rw] code_challenge_method
    #   The PKCE code challenge method (S256).
    #   @return [String, nil]
    attr_accessor :code_challenge_method

    # @!attribute [rw] redirect_uri
    #   The URI to redirect to after authorization.
    #   @return [String, nil]
    attr_accessor :redirect_uri

    # @!attribute [rw] response_type
    #   The OAuth response type (code).
    #   @return [String]
    attr_accessor :response_type

    # @!attribute [rw] state
    #   The state parameter for CSRF protection.
    #   @return [String, nil]
    attr_accessor :state

    validates :response_type, presence: true, inclusion: {in: VALID_RESPONSE_TYPES}

    validate :token_authority_client_must_be_valid
    validate :client_id_must_be_valid
    validate :pkce_params_must_be_valid
    validate :redirect_uri_must_be_valid
    validate :resources_must_be_valid
    validate :scope_must_be_valid

    # Deserializes an authorization request from an internal state token.
    #
    # The state token is a JWT that preserves the authorization request parameters
    # during the consent flow. This allows the request to survive redirects to
    # the consent screen and back.
    #
    # @param token [String] the JWT state token
    #
    # @return [TokenAuthority::AuthorizationRequest] the deserialized request
    #
    # @note If the client cannot be resolved, token_authority_client will be nil
    #   and validation will fail.
    def self.from_internal_state_token(token)
      attributes = TokenAuthority::JsonWebToken.decode(token)
      token_authority_client = TokenAuthority::ClientIdResolver.resolve(attributes[:token_authority_client])
      new(
        **attributes.except(:token_authority_client, :exp).merge(token_authority_client:)
      )
    rescue TokenAuthority::ClientNotFoundError
      new(**attributes.except(:token_authority_client, :exp).merge(token_authority_client: nil))
    end

    # Converts the authorization request to a hash for serialization.
    #
    # @return [Hash] the request parameters
    def to_h
      {
        token_authority_client: token_authority_client.public_id,
        client_id:,
        state:,
        code_challenge:,
        code_challenge_method:,
        redirect_uri:,
        response_type:,
        resources:,
        scope:
      }
    end

    # Serializes the authorization request to an internal state token.
    #
    # The state token is used to preserve authorization request parameters
    # during the consent flow without storing them in the session.
    #
    # @return [String] the JWT state token
    def to_internal_state_token
      TokenAuthority::JsonWebToken.encode(to_h)
    end

    private

    def token_authority_client_must_be_valid
      errors.add(:token_authority_client, :invalid) unless valid_token_authority_client?
    end

    def client_id_must_be_valid
      return unless valid_token_authority_client?

      # For URL-based clients, client_id must match the URL
      if token_authority_client.is_a?(TokenAuthority::ClientMetadataDocument)
        errors.add(:client_id, :blank) and return if client_id.blank?
        errors.add(:client_id, :mismatched) and return if client_id != token_authority_client.public_id
        return
      end

      # For registered clients
      return if token_authority_client.confidential_client_type? && client_id.blank?

      errors.add(:client_id, :blank) and return if client_id.blank?

      client = TokenAuthority::Client.find_by(public_id: client_id)
      errors.add(:client_id, :unregistered_client) unless client
    end

    def pkce_params_must_be_valid
      return unless valid_token_authority_client?

      # URL-based clients are always public and must use PKCE
      if token_authority_client.public_client_type?
        validate_public_pkce_params
      else
        validate_confidential_pkce_params
      end
    end

    def validate_public_pkce_params
      return unless valid_token_authority_client?
      return unless token_authority_client.public_client_type?

      errors.add(:code_challenge, :required_for_public_clients) if code_challenge.blank?
      errors.add(:code_challenge_method, :required_for_public_clients) if code_challenge_method.blank?
      errors.add(:code_challenge_method, :invalid) unless code_challenge_method.in?(VALID_CODE_CHALLENGE_METHODS)
    end

    def validate_confidential_pkce_params
      return unless valid_token_authority_client?
      return unless token_authority_client.confidential_client_type?
      return unless code_challenge.present? || code_challenge_method.present?

      errors.add(:code_challenge, :required_if_other_pkce_params_present) if code_challenge.blank?
      errors.add(:code_challenge_method, :required_if_other_pkce_params_present) if code_challenge_method.blank?
      errors.add(:code_challenge_method, :invalid) unless code_challenge_method.in?(VALID_CODE_CHALLENGE_METHODS)
    end

    def redirect_uri_must_be_valid
      return unless valid_token_authority_client?

      if token_authority_client.public_client_type?
        validate_public_client_redirect_uri
      else
        validate_confidential_client_redirect_uri
      end
    end

    def validate_public_client_redirect_uri
      errors.add(:redirect_uri, :blank) if redirect_uri.blank?
      validate_redirect_uris_match
    end

    def validate_confidential_client_redirect_uri
      return if redirect_uri.blank?

      validate_redirect_uris_match
    end

    def validate_redirect_uris_match
      errors.add(:redirect_uri, :invalid) unless token_authority_client.redirect_uri_registered?(redirect_uri)
    end

    def valid_token_authority_client?
      token_authority_client.is_a?(TokenAuthority::Client) ||
        token_authority_client.is_a?(TokenAuthority::ClientMetadataDocument)
    end

    def resources_must_be_valid
      # Check if resource is required
      if TokenAuthority.config.require_resource && resources.empty?
        errors.add(:resources, :required)
        return
      end

      return if resources.empty?

      # If resources are provided but feature is disabled, reject them
      unless TokenAuthority.config.resources_enabled?
        errors.add(:resources, :not_allowed)
        return
      end

      # Validate all resource URIs
      unless valid_resource_uris?
        errors.add(:resources, :invalid_uri)
        return
      end

      # Check against allowed resources list
      errors.add(:resources, :not_allowed) unless allowed_resources?
    end

    def scope_must_be_valid
      # Check if scope is required
      if TokenAuthority.config.require_scope && scope.blank?
        errors.add(:scope, :required)
        return
      end

      return if scope.blank?

      # If scopes are provided but feature is disabled, reject them
      unless TokenAuthority.config.scopes_enabled?
        errors.add(:scope, :not_allowed)
        return
      end

      # Validate all scope tokens
      unless valid_scope_tokens?
        errors.add(:scope, :invalid)
        return
      end

      # Check against allowed scopes list
      errors.add(:scope, :not_allowed) unless allowed_scopes?
    end
  end
end
