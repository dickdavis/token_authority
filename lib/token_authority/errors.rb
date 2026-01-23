# frozen_string_literal: true

module TokenAuthority
  ##
  # Error for when the configuration is invalid.
  class ConfigurationError < StandardError; end

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

  # RFC 7591 Dynamic Client Registration errors

  ##
  # Error for when one or more redirect_uris are invalid.
  class InvalidRedirectUrisError < StandardError
    def initialize(msg = "One or more redirect_uris are invalid")
      super
    end
  end

  ##
  # Error for when client metadata is invalid.
  class InvalidClientMetadataError < StandardError
    def initialize(msg = "Client metadata is invalid")
      super
    end
  end

  ##
  # Error for when software statement is invalid or could not be verified.
  class InvalidSoftwareStatementError < StandardError
    def initialize(msg = "Software statement is invalid or could not be verified")
      super
    end
  end

  ##
  # Error for when software statement is not approved for use.
  class UnapprovedSoftwareStatementError < StandardError
    def initialize(msg = "Software statement is not approved for use with this authorization server")
      super
    end
  end

  ##
  # Error for when initial access token is invalid or missing.
  class InvalidInitialAccessTokenError < StandardError
    def initialize(msg = "Initial access token is invalid or missing")
      super
    end
  end

  # Client Metadata Document errors

  ##
  # Error for when the client_id URL is invalid (not HTTPS, has fragment, etc.)
  class InvalidClientMetadataDocumentUrlError < StandardError
    def initialize(msg = "Client ID URL is invalid")
      super
    end
  end

  ##
  # Error for when fetching the client metadata document fails.
  class ClientMetadataDocumentFetchError < StandardError
    def initialize(msg = "Failed to fetch client metadata document")
      super
    end
  end

  ##
  # Error for when the client metadata document content is invalid.
  class InvalidClientMetadataDocumentError < StandardError
    def initialize(msg = "Client metadata document is invalid")
      super
    end
  end
end
