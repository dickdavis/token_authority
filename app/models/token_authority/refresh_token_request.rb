# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a refresh token request
  class RefreshTokenRequest
    include ActiveModel::Model
    include ActiveModel::Validations
    include TokenAuthority::Resourceable
    include TokenAuthority::Scopeable

    attr_accessor :token, :client_id

    validate :token_authority_session_must_be_valid
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

    # Returns the session for use in refresh operation
    def token_authority_session
      return nil unless token

      @token_authority_session ||= TokenAuthority::Session.find_by(refresh_token_jti: token.jti)
    end

    # Returns the resolved client_id (from param or from grant's client)
    def resolved_client_id
      client_id.presence || token_authority_session&.token_authority_authorization_grant&.resolved_client&.public_id
    end

    private

    def token_authority_session_must_be_valid
      errors.add(:token, :blank) and return if token.blank?

      errors.add(:token, :session_not_found) if token_authority_session.nil?
    end

    def token_authority_authorization_grant
      @token_authority_authorization_grant ||= token_authority_session&.token_authority_authorization_grant
    end

    def resources_must_be_valid
      return unless token_authority_session_valid?
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
      unless allowed_resources?
        errors.add(:resources, :not_allowed)
        return
      end

      # Check that requested resources are a subset of granted resources (downscoping)
      granted_resources = token_authority_authorization_grant.resources
      errors.add(:resources, :not_subset) unless resources_subset_of?(granted_resources)
    end

    def scope_must_be_valid
      return unless token_authority_session_valid?
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

    def token_authority_session_valid?
      return @token_authority_session_valid if defined?(@token_authority_session_valid)

      @token_authority_session_valid = token_authority_session.present?
    end
  end
end
