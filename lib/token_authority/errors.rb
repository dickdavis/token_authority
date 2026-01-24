# frozen_string_literal: true

module TokenAuthority
  # Raised when the TokenAuthority configuration is invalid or inconsistent.
  # This typically occurs during initialization or validation when required
  # configuration options are missing or conflicting.
  #
  # @since 0.2.0
  class ConfigurationError < StandardError; end

  # Raised when the client attempting to use a token or grant doesn't match
  # the client that originally requested it. This prevents token theft and
  # unauthorized client access.
  #
  # @since 0.2.0
  class ClientMismatchError < StandardError; end

  # Raised when a requested OAuth client cannot be found in the database or
  # via client metadata document resolution.
  #
  # @since 0.2.0
  class ClientNotFoundError < StandardError; end

  # Raised when an access token fails validation (expired, malformed, or invalid signature).
  #
  # @since 0.2.0
  class InvalidAccessTokenError < StandardError; end

  # Raised when an authorization grant is invalid, expired, already redeemed,
  # or the PKCE code verifier doesn't match the challenge.
  #
  # Uses I18n for the error message to support internationalization.
  #
  # @since 0.2.0
  class InvalidGrantError < StandardError
    # Returns the localized error message.
    # @return [String] the error message
    def message
      I18n.t("token_authority.errors.invalid_grant")
    end
  end

  # Raised when a client's redirect URI cannot be parsed or is otherwise invalid.
  # This prevents open redirect vulnerabilities.
  #
  # @since 0.2.0
  class InvalidRedirectUrlError < StandardError; end

  # Raised when a protected endpoint is accessed without the required Authorization header.
  #
  # @since 0.2.0
  class MissingAuthorizationHeaderError < StandardError; end

  # Raised when an OAuth session cannot be found by token JTI or session ID.
  #
  # @since 0.2.0
  class OAuthSessionNotFound < StandardError; end

  # Raised when attempting to use a revoked session.
  # This can indicate a refresh token replay attack where a stolen token
  # is used after the legitimate client has already refreshed.
  #
  # Captures context about both the session being refreshed and the session
  # that was revoked to aid in security auditing.
  #
  # @since 0.2.0
  class RevokedSessionError < StandardError
    # @return [String] the client ID that attempted the refresh
    attr_reader :client_id

    # @return [Integer] the session ID that was being refreshed
    attr_reader :refreshed_session_id

    # @return [Integer] the session ID that was revoked
    attr_reader :revoked_session_id

    # @return [Integer] the user ID associated with the session
    attr_reader :user_id

    # Creates a new RevokedSessionError with security context.
    #
    # @param client_id [String] the client ID
    # @param refreshed_session_id [Integer] the session being refreshed
    # @param revoked_session_id [Integer] the session that was revoked
    # @param user_id [Integer] the user ID
    def initialize(client_id:, refreshed_session_id:, revoked_session_id:, user_id:)
      super()
      @client_id = client_id
      @refreshed_session_id = refreshed_session_id
      @revoked_session_id = revoked_session_id
      @user_id = user_id
    end

    # Returns the localized error message with context.
    # @return [String] the error message
    def message
      I18n.t("token_authority.errors.revoked_session", client_id:, refreshed_session_id:, revoked_session_id:, user_id:)
    end
  end

  # Raised for unexpected server-side errors during OAuth flows.
  # This is a catch-all for internal processing errors.
  #
  # @since 0.2.0
  class ServerError < StandardError; end

  # Raised when an access token is valid but the user is not authorized
  # to access the requested resource.
  #
  # @since 0.2.0
  class UnauthorizedAccessTokenError < StandardError; end

  # Raised when PKCE code challenge verification fails.
  # This indicates the code_verifier doesn't match the original code_challenge,
  # which could indicate an interception attack.
  #
  # @since 0.2.0
  class UnsuccessfulChallengeError < StandardError; end

  # Raised when a client requests a grant type that is not supported
  # by the authorization server.
  #
  # @since 0.2.0
  class UnsupportedGrantTypeError < StandardError; end

  # Raised during client registration (RFC 7591) when one or more
  # redirect URIs are malformed or use an invalid scheme.
  #
  # @since 0.2.0
  class InvalidRedirectUrisError < StandardError
    # Creates a new InvalidRedirectUrisError.
    # @param msg [String] custom error message
    def initialize(msg = "One or more redirect_uris are invalid")
      super
    end
  end

  # Raised during client registration (RFC 7591) when the submitted
  # client metadata fails validation.
  #
  # @since 0.2.0
  class InvalidClientMetadataError < StandardError
    # Creates a new InvalidClientMetadataError.
    # @param msg [String] custom error message
    def initialize(msg = "Client metadata is invalid")
      super
    end
  end

  # Raised during client registration (RFC 7591) when a software statement
  # JWT cannot be verified or contains invalid claims.
  #
  # @since 0.2.0
  class InvalidSoftwareStatementError < StandardError
    # Creates a new InvalidSoftwareStatementError.
    # @param msg [String] custom error message
    def initialize(msg = "Software statement is invalid or could not be verified")
      super
    end
  end

  # Raised during client registration (RFC 7591) when a software statement
  # is valid but not approved for use with this authorization server.
  #
  # @since 0.2.0
  class UnapprovedSoftwareStatementError < StandardError
    # Creates a new UnapprovedSoftwareStatementError.
    # @param msg [String] custom error message
    def initialize(msg = "Software statement is not approved for use with this authorization server")
      super
    end
  end

  # Raised during client registration (RFC 7591) when an initial access token
  # is required but missing or fails validation.
  #
  # @since 0.2.0
  class InvalidInitialAccessTokenError < StandardError
    # Creates a new InvalidInitialAccessTokenError.
    # @param msg [String] custom error message
    def initialize(msg = "Initial access token is invalid or missing")
      super
    end
  end

  # Raised when a client_id URL for client metadata documents is invalid.
  # URLs must be HTTPS, not contain fragments, and meet other security requirements.
  #
  # @since 0.2.0
  class InvalidClientMetadataDocumentUrlError < StandardError
    # Creates a new InvalidClientMetadataDocumentUrlError.
    # @param msg [String] custom error message
    def initialize(msg = "Client ID URL is invalid")
      super
    end
  end

  # Raised when fetching a client metadata document fails due to network errors,
  # timeouts, or HTTP error responses.
  #
  # @since 0.2.0
  class ClientMetadataDocumentFetchError < StandardError
    # Creates a new ClientMetadataDocumentFetchError.
    # @param msg [String] custom error message
    def initialize(msg = "Failed to fetch client metadata document")
      super
    end
  end

  # Raised when a fetched client metadata document contains invalid JSON
  # or doesn't meet the required schema.
  #
  # @since 0.2.0
  class InvalidClientMetadataDocumentError < StandardError
    # Creates a new InvalidClientMetadataDocumentError.
    # @param msg [String] custom error message
    def initialize(msg = "Client metadata document is invalid")
      super
    end
  end

  # Raised when no protected resource configuration exists for the requested subdomain.
  #
  # This error occurs in the RFC 9728 protected resource metadata endpoint when:
  # 1. A subdomain-specific request arrives but that subdomain isn't in protected_resources
  # 2. The fallback protected_resource configuration is also empty or nil
  # 3. A bare domain request arrives but protected_resource isn't configured
  #
  # The ResourceMetadataController catches this error and returns HTTP 404, which is
  # semantically correct: the client is asking about a resource that doesn't exist in
  # the configuration. This differs from a 500 error which would imply a server problem.
  #
  # This separation of concerns (model raises domain error, controller maps to HTTP status)
  # keeps the model focused on business logic without coupling it to HTTP semantics.
  #
  # @example Subdomain not configured
  #   # config.protected_resources = { "api" => {...} }
  #   # Request to mcp.example.com/.well-known/oauth-protected-resource
  #   # Raises this error because "mcp" isn't configured
  #
  # @see ResourceMetadataController#show
  # @since 0.3.0
  class ResourceNotConfiguredError < StandardError
    # Creates a new ResourceNotConfiguredError.
    # @param msg [String] custom error message
    def initialize(msg = "No protected resource configuration found for this subdomain")
      super
    end
  end
end
