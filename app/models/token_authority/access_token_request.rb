# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a access token request
  class AccessTokenRequest
    include ActiveModel::Model
    include ActiveModel::Validations
    include TokenAuthority::Resourceable
    include TokenAuthority::Scopeable

    attr_accessor :code_verifier, :token_authority_authorization_grant, :redirect_uri

    validate :token_authority_authorization_grant_must_be_valid
    validate :code_verifier_must_be_valid
    validate :redirect_uri_must_be_valid
    validate :resources_must_be_valid
    validate :scope_must_be_valid

    # Returns the effective resources (requested or falls back to grant's resources)
    def effective_resources
      return resources if resources.any?

      token_authority_authorization_grant&.resources || []
    end

    # Returns the effective scopes (requested or falls back to grant's scopes)
    def effective_scopes
      return scope if scope.present?

      token_authority_authorization_grant&.scopes || []
    end

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
      token_authority_authorization_grant.code_challenge.present? || token_authority_authorization_grant.code_challenge_method.present?
    end

    def validate_code_verifier_matches_code_challenge
      challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
      errors.add(:code_verifier, :does_not_validate_code_challenge) unless token_authority_authorization_grant.code_challenge == challenge
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
      errors.add(:redirect_uri, :mismatched) unless token_authority_authorization_grant.redirect_uri == redirect_uri
    end

    def redirect_uri_param_present_in_authorize?
      token_authority_authorization_grant.redirect_uri.present?
    end

    def token_authority_authorization_grant_present?
      return @token_authority_authorization_grant_present if defined?(@token_authority_authorization_grant_present)

      @token_authority_authorization_grant_present = token_authority_authorization_grant&.is_a?(TokenAuthority::AuthorizationGrant)
    end

    def token_authority_client
      @token_authority_client ||= token_authority_authorization_grant.resolved_client
    end

    def resources_must_be_valid
      return unless token_authority_authorization_grant_present?
      return if resources.empty?

      # If resources are provided but feature is disabled, reject them
      unless TokenAuthority.config.rfc_8707_enabled?
        errors.add(:resources, :not_allowed)
        return
      end

      # Validate all resource URIs
      unless valid_resource_uris?
        errors.add(:resources, :invalid_uri)
        return
      end

      # Check against allowed resources list
      unless allowed_resources?
        errors.add(:resources, :not_allowed)
        return
      end

      # Check that requested resources are a subset of granted resources (downscoping)
      granted_resources = token_authority_authorization_grant.resources
      errors.add(:resources, :not_subset) unless resources_subset_of?(granted_resources)
    end

    def scope_must_be_valid
      return unless token_authority_authorization_grant_present?
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
      unless allowed_scopes?
        errors.add(:scope, :not_allowed)
        return
      end

      # Check that requested scopes are a subset of granted scopes (downscoping)
      granted_scopes = token_authority_authorization_grant.scopes || []
      errors.add(:scope, :not_subset) unless scopes_subset_of?(granted_scopes)
    end
  end
end
