# frozen_string_literal: true

module TokenAuthority
  # Represents an OAuth token session containing access and refresh tokens.
  #
  # Sessions track the lifecycle of token pairs from creation through expiration,
  # refresh, or revocation. They implement refresh token rotation (each refresh
  # creates a new session) and revocation detection to prevent replay attacks.
  #
  # The session stores JWT identifiers (jti claims) for both access and refresh
  # tokens, but not the tokens themselves. This allows efficient revocation lookups
  # without storing the full JWT payloads.
  #
  # Session status transitions:
  # - created: Active session with valid tokens
  # - refreshed: Old session that was replaced by a refresh operation
  # - expired: Session that exceeded its lifetime (future use)
  # - revoked: Session that was explicitly revoked or detected as compromised
  #
  # @example Refreshing a session
  #   new_session = session.refresh(
  #     token: refresh_token,
  #     client_id: client.public_id,
  #     resources: ["https://api.example.com"]
  #   )
  #
  # @example Revoking a session
  #   session.revoke_self_and_active_session(
  #     reason: "user_logout",
  #     request_id: "req-123"
  #   )
  #
  # @since 0.2.0
  class Session < ApplicationRecord
    include TokenAuthority::SessionCreatable
    include TokenAuthority::EventLogging

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

    # Refreshes the session by creating a new session with rotated tokens.
    #
    # This implements refresh token rotation as recommended by OAuth 2.1.
    # The current session is marked as "refreshed" and a new session is created
    # with new access and refresh tokens.
    #
    # Includes replay attack detection: if the session is not in "created" status
    # or the client_id doesn't match, the refresh token has been stolen or reused.
    # In this case, both the current session and any active session are revoked.
    #
    # @param token [TokenAuthority::RefreshToken] the refresh token to validate
    # @param client_id [String] the client ID attempting the refresh
    # @param resources [Array<String>] resource indicators for the new tokens
    # @param scopes [Array<String>] scopes for the new tokens
    #
    # @return [TokenAuthority::Session] the newly created session
    #
    # @raise [TokenAuthority::ServerError] if the token JTI doesn't match
    # @raise [TokenAuthority::InvalidGrantError] if the token is invalid
    # @raise [TokenAuthority::RevokedSessionError] if replay attack is detected
    def refresh(token:, client_id:, resources: [], scopes: [])
      instrument("session.refresh") do
        raise TokenAuthority::ServerError, I18n.t("token_authority.errors.mismatched_refresh_token") unless token.jti == refresh_token_jti
        raise TokenAuthority::InvalidGrantError unless token.valid?

        # Detect stolen refresh token and replay attacks, and then revoke current active token authority session
        unless created_status? && client_id == token_authority_authorization_grant.resolved_client.public_id
          session = token_authority_authorization_grant.active_token_authority_session || self
          session.update(status: "revoked")
          raise TokenAuthority::RevokedSessionError.new(
            client_id:,
            refreshed_session_id: id,
            revoked_session_id: session.id,
            user_id:
          )
        end

        create_token_authority_session(grant: token_authority_authorization_grant, resources:, scopes:) do
          update(status: "refreshed")
        end
      end
    rescue TokenAuthority::ServerError => error
      raise TokenAuthority::ServerError, error.message
    end

    # Revokes this session and any active session for the same authorization grant.
    #
    # This ensures that revoking any token (access or refresh) invalidates the
    # entire token family, preventing continued use after revocation. Emits a
    # security event for audit logging.
    #
    # @param reason [String] the reason for revocation (default: "revocation_requested")
    # @param request_id [String, nil] the request ID for correlation in logs
    #
    # @return [void]
    #
    # @example
    #   session.revoke_self_and_active_session(
    #     reason: "user_logout",
    #     request_id: request.uuid
    #   )
    def revoke_self_and_active_session(reason: "revocation_requested", request_id: nil)
      instrument("session.revoke") do
        related_session_ids = []
        ActiveRecord::Base.transaction do
          update(status: "revoked")
          active_session = token_authority_authorization_grant.active_token_authority_session
          if active_session && active_session.id != id
            active_session.update(status: "revoked")
            related_session_ids << active_session.id
          end
        end

        notify_event("security.session.revoked",
          request_id: request_id,
          session_id: id,
          client_id: token_authority_authorization_grant.resolved_client&.public_id,
          reason: reason,
          related_session_ids: related_session_ids)
      end
    end

    # Revokes the session associated with a token JTI.
    #
    # Searches for a session by either access token or refresh token JTI.
    # This is the generic revocation method used when the token type is unknown.
    #
    # @param jti [String] the JWT identifier from the token
    #
    # @return [void]
    #
    # @note Returns silently if no session is found
    def self.revoke_for_token(jti:)
      # Must use find_by in this manner due to AR encryption
      token_authority_session = find_by(access_token_jti: jti) || find_by(refresh_token_jti: jti)
      execute_revocation(token_authority_session:)
    end

    # Revokes the session associated with an access token JTI.
    #
    # More efficient than revoke_for_token when the token type is known.
    #
    # @param access_token_jti [String] the access token's JWT identifier
    #
    # @return [void]
    def self.revoke_for_access_token(access_token_jti:)
      token_authority_session = find_by(access_token_jti:)
      execute_revocation(token_authority_session:)
    end

    # Revokes the session associated with a refresh token JTI.
    #
    # More efficient than revoke_for_token when the token type is known.
    #
    # @param refresh_token_jti [String] the refresh token's JWT identifier
    #
    # @return [void]
    def self.revoke_for_refresh_token(refresh_token_jti:)
      token_authority_session = find_by(refresh_token_jti:)
      execute_revocation(token_authority_session:)
    end

    class << self
      # Internal helper to execute the revocation of a session.
      #
      # @param token_authority_session [TokenAuthority::Session, nil] the session to revoke
      #
      # @return [void]
      #
      # @api private
      def execute_revocation(token_authority_session:)
        return if token_authority_session.blank?

        token_authority_session.revoke_self_and_active_session
      end
    end
  end
end
