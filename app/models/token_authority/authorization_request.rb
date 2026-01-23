# frozen_string_literal: true

module TokenAuthority
  ##
  # Models an authorization request token
  class AuthorizationRequest
    include ActiveModel::Model
    include ActiveModel::Validations

    VALID_CODE_CHALLENGE_METHODS = ["S256"].freeze
    VALID_RESPONSE_TYPES = ["code"].freeze

    attr_accessor :token_authority_client, :client_id,
      :code_challenge, :code_challenge_method,
      :redirect_uri, :response_type, :state, :resources

    validates :response_type, presence: true, inclusion: {in: VALID_RESPONSE_TYPES}

    validate :token_authority_client_must_be_valid
    validate :client_id_must_be_valid
    validate :pkce_params_must_be_valid
    validate :redirect_uri_must_be_valid
    validate :resources_must_be_valid

    def self.from_internal_state_token(token)
      attributes = TokenAuthority::JsonWebToken.decode(token)
      token_authority_client = TokenAuthority::ClientIdResolver.resolve(attributes[:token_authority_client])
      new(
        **attributes.except(:token_authority_client, :exp).merge(token_authority_client:)
      )
    rescue TokenAuthority::ClientNotFoundError
      new(**attributes.except(:token_authority_client, :exp).merge(token_authority_client: nil))
    end

    def to_h
      {
        token_authority_client: token_authority_client.public_id,
        client_id:,
        state:,
        code_challenge:,
        code_challenge_method:,
        redirect_uri:,
        response_type:,
        resources: resources || []
      }
    end

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
      normalized_resources = resources || []

      # Check if resource is required
      if TokenAuthority.config.rfc_8707_require_resource && normalized_resources.empty?
        errors.add(:resources, :required)
        return
      end

      return if normalized_resources.empty?

      # If resources are provided but feature is disabled, reject them
      unless TokenAuthority.config.rfc_8707_enabled?
        errors.add(:resources, :not_allowed)
        return
      end

      # Validate all resource URIs
      unless TokenAuthority::ResourceUriValidator.valid_all?(normalized_resources)
        errors.add(:resources, :invalid_uri)
        return
      end

      # Check against allowed resources list
      unless TokenAuthority::ResourceUriValidator.allowed_all?(normalized_resources)
        errors.add(:resources, :not_allowed)
      end
    end
  end
end
