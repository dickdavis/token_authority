# frozen_string_literal: true

module TokenAuthority
  ##
  # TokenAuthority::Client model
  class Client < ApplicationRecord
    CLIENT_TYPE_ENUM_VALUES = {public: "public", confidential: "confidential"}.freeze

    enum :client_type, CLIENT_TYPE_ENUM_VALUES, suffix: true

    validates :name, presence: true, length: {minimum: 3, maximum: 255}
    validates :access_token_duration, numericality: {only_integer: true, greater_than: 0}
    validates :refresh_token_duration, numericality: {only_integer: true, greater_than: 0}
    validates :redirect_uri, presence: true
    validate :redirect_uri_is_valid_uri

    before_create :generate_client_secret_id
    before_create :generate_public_id

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
      uri = URI(redirect_uri)
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

    private

    def redirect_uri_is_valid_uri
      uri = URI.parse(redirect_uri)
      errors.add(:redirect_uri, :invalid_http_scheme) unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
    rescue URI::InvalidURIError
      errors.add(:redirect_uri, :invalid_uri)
    end

    def generate_client_secret_id
      return if client_type == "public"

      self.client_secret_id = SecureRandom.uuid
    end

    def generate_public_id
      self.public_id = SecureRandom.uuid
    end

    def generate_client_secret_for(secret_id)
      OpenSSL::HMAC.hexdigest("SHA256", TokenAuthority.config.secret_key, secret_id)
    end
  end
end
