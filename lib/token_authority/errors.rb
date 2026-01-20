# frozen_string_literal: true

module TokenAuthority
  ##
  # Error for when the OAuth client is mismatched.
  class ClientMismatchError < StandardError; end

  ##
  # Error for when the OAuth client is not found.
  class ClientNotFoundError < StandardError; end

  ##
  # Error for when an invalid access token is provided.
  class InvalidAccessTokenError < StandardError; end

  ##
  # Error for when a grant is invalid
  class InvalidGrantError < StandardError
    def message
      I18n.t("token_authority.errors.invalid_grant")
    end
  end

  ##
  # Error for when client redirection URI is invalid.
  class InvalidRedirectUrlError < StandardError; end

  ##
  # Error for when an authorization header is not provided.
  class MissingAuthorizationHeaderError < StandardError; end

  ##
  # Error for when OAuth Session is not found.
  class OAuthSessionNotFound < StandardError; end

  ##
  # Error for when an OAuthSession is revoked.
  class RevokedSessionError < StandardError
    attr_reader :client_id, :refreshed_session_id, :revoked_session_id, :user_id

    def initialize(client_id:, refreshed_session_id:, revoked_session_id:, user_id:)
      super()
      @client_id = client_id
      @refreshed_session_id = refreshed_session_id
      @revoked_session_id = revoked_session_id
      @user_id = user_id
    end

    def message
      I18n.t("token_authority.errors.revoked_session", client_id:, refreshed_session_id:, revoked_session_id:, user_id:)
    end
  end

  ##
  # Error for when server experiences an error.
  class ServerError < StandardError; end

  ##
  # Error for when an unauthorized access token is provided.
  class UnauthorizedAccessTokenError < StandardError; end

  ##
  # Error for when a PKCE challenge has failed.
  class UnsuccessfulChallengeError < StandardError; end

  ##
  # Error for when client provides an unsupported grant type param.
  class UnsupportedGrantTypeError < StandardError; end
end
