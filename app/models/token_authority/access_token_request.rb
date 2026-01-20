# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a access token request
  class AccessTokenRequest
    include ActiveModel::Model
    include ActiveModel::Validations

    attr_accessor :code_verifier, :token_authority_authorization_grant, :redirect_uri

    validate :token_authority_authorization_grant_must_be_valid
    validate :code_verifier_must_be_valid
    validate :redirect_uri_must_be_valid

    private

    def token_authority_authorization_grant_must_be_valid
      errors.add(:token_authority_authorization_grant, :invalid) and return unless token_authority_authorization_grant_present?

      errors.add(:token_authority_authorization_grant, :redeemed) if token_authority_authorization_grant.redeemed?
    end

    def code_verifier_must_be_valid
      return unless token_authority_authorization_grant_present?

      if token_authority_client.public_client_type?
        validate_code_verifier_for_public
      else
        validate_code_verifier_for_confidential
      end
    end

    def validate_code_verifier_for_public
      errors.add(:code_verifier, :blank) and return if code_verifier.blank?

      validate_code_verifier_matches_code_challenge
    end

    def validate_code_verifier_for_confidential
      return unless challenge_required?

      if code_verifier.blank? && challenge_params_present_in_authorize?
        errors.add(:code_verifier, :present_in_authorize) and return
      end

      validate_code_verifier_matches_code_challenge
    end

    def challenge_required?
      code_verifier.present? || challenge_params_present_in_authorize?
    end

    def challenge_params_present_in_authorize?
      token_authority_challenge.code_challenge.present? || token_authority_challenge.code_challenge_method.present?
    end

    def validate_code_verifier_matches_code_challenge
      challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
      errors.add(:code_verifier, :does_not_validate_code_challenge) unless token_authority_challenge.code_challenge == challenge
    end

    def redirect_uri_must_be_valid
      return unless token_authority_authorization_grant_present?

      if token_authority_client.public_client_type?
        validate_redirect_uri_for_public
      else
        validate_redirect_uri_for_confidential
      end
    end

    def validate_redirect_uri_for_public
      errors.add(:redirect_uri, :blank) and return if redirect_uri.blank?

      validate_redirect_uri_matches_authorize_param
    end

    def validate_redirect_uri_for_confidential
      return unless redirect_uri.present? || redirect_uri_param_present_in_authorize?

      errors.add(:redirect_uri, :present_in_authorize) and return if redirect_uri.blank?

      validate_redirect_uri_matches_authorize_param
    end

    def validate_redirect_uri_matches_authorize_param
      errors.add(:redirect_uri, :mismatched) unless token_authority_challenge.redirect_uri == redirect_uri
    end

    def redirect_uri_param_present_in_authorize?
      token_authority_challenge.redirect_uri.present?
    end

    def token_authority_authorization_grant_present?
      return @token_authority_authorization_grant_present if defined?(@token_authority_authorization_grant_present)

      @token_authority_authorization_grant_present = token_authority_authorization_grant&.is_a?(TokenAuthority::AuthorizationGrant)
    end

    def token_authority_client
      @token_authority_client ||= token_authority_authorization_grant.token_authority_client
    end

    def token_authority_challenge
      @token_authority_challenge ||= token_authority_authorization_grant.token_authority_challenge
    end
  end
end
