# frozen_string_literal: true

module TokenAuthority
  ##
  # TokenAuthority::Client model
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

    def new_authorization_grant(user:, challenge_params: {})
      TokenAuthority::AuthorizationGrant.create(token_authority_client: self, user:, token_authority_challenge_attributes: challenge_params)
    end

    def new_authorization_request(client_id:, code_challenge:, code_challenge_method:, redirect_uri:, response_type:, state:)
      TokenAuthority::AuthorizationRequest.new(
        token_authority_client: self,
        client_id:,
        state:,
        code_challenge:,
        code_challenge_method:,
        redirect_uri:,
        response_type:
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

    def client_secret
      return nil if client_type == "public" || client_secret_id.blank?

      generate_client_secret_for(client_secret_id)
    end

    def authenticate_with_secret(provided_secret)
      return false if client_type == "public" || client_secret_id.blank?
      return false if provided_secret.blank?

      # Use secure comparison to prevent timing attacks
      ActiveSupport::SecurityUtils.secure_compare(
        client_secret,
        provided_secret
      )
    end

    def redirect_uri_registered?(uri)
      redirect_uris&.include?(uri)
    end

    def primary_redirect_uri
      redirect_uris&.first
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
      self.access_token_duration ||= TokenAuthority.config.rfc_9068_default_access_token_duration
      self.refresh_token_duration ||= TokenAuthority.config.rfc_9068_default_refresh_token_duration
    end

    def set_client_id_issued_at
      self.client_id_issued_at = Time.current
    end

    def set_client_secret_expiration
      return if client_type == "public"
      return unless TokenAuthority.config.rfc_7591_client_secret_expiration

      self.client_secret_expires_at = Time.current + TokenAuthority.config.rfc_7591_client_secret_expiration
    end

    def generate_client_secret_for(secret_id)
      OpenSSL::HMAC.hexdigest("SHA256", TokenAuthority.config.secret_key, secret_id)
    end
  end
end
