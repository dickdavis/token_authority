# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a token authority session with minimal data from session.
  class Session < ApplicationRecord
    include TokenAuthority::SessionCreatable

    STATUS_ENUM_VALUES = {
      created: "created",
      expired: "expired",
      refreshed: "refreshed",
      revoked: "revoked"
    }.freeze

    VALID_UUID_REGEX = /[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}/i

    belongs_to :token_authority_authorization_grant, class_name: "TokenAuthority::AuthorizationGrant"

    enum :status, STATUS_ENUM_VALUES, suffix: true

    delegate :user_id, to: :token_authority_authorization_grant

    validates :access_token_jti, presence: true, uniqueness: true, format: {with: VALID_UUID_REGEX}
    validates :refresh_token_jti, presence: true, uniqueness: true, format: {with: VALID_UUID_REGEX}

    def refresh(token:, client_id:)
      raise TokenAuthority::ServerError, I18n.t("token_authority.errors.mismatched_refresh_token") unless token.jti == refresh_token_jti
      raise TokenAuthority::InvalidGrantError unless token.valid?

      # Detect stolen refresh token and replay attacks, and then revoke current active token authority session
      unless created_status? && client_id == token_authority_authorization_grant.token_authority_client.public_id
        session = token_authority_authorization_grant.active_token_authority_session || self
        session.update(status: "revoked")
        raise TokenAuthority::RevokedSessionError.new(
          client_id:,
          refreshed_session_id: id,
          revoked_session_id: session.id,
          user_id:
        )
      end

      create_token_authority_session(grant: token_authority_authorization_grant) do
        update(status: "refreshed")
      end
    rescue TokenAuthority::ServerError => error
      raise TokenAuthority::ServerError, error.message
    end

    def revoke_self_and_active_session
      ActiveRecord::Base.transaction do
        update(status: "revoked")
        token_authority_authorization_grant.active_token_authority_session&.update(status: "revoked")
      end
    end

    def self.revoke_for_token(jti:)
      # Must use find_by in this manner due to AR encryption
      token_authority_session = find_by(access_token_jti: jti) || find_by(refresh_token_jti: jti)
      execute_revocation(token_authority_session:)
    end

    def self.revoke_for_access_token(access_token_jti:)
      token_authority_session = find_by(access_token_jti:)
      execute_revocation(token_authority_session:)
    end

    def self.revoke_for_refresh_token(refresh_token_jti:)
      token_authority_session = find_by(refresh_token_jti:)
      execute_revocation(token_authority_session:)
    end

    class << self
      def execute_revocation(token_authority_session:)
        return if token_authority_session.blank?

        token_authority_session.revoke_self_and_active_session
      end
    end
  end
end
