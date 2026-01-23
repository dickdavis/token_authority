# frozen_string_literal: true

module TokenAuthority
  # Provides JWT access token authentication for protected API endpoints.
  #
  # This concern enables host applications to protect their API endpoints using
  # JWT access tokens issued by TokenAuthority. It validates tokens, checks
  # session status, and provides helper methods to access the authenticated user
  # and token scopes.
  #
  # The concern automatically:
  # - Extracts and validates the Bearer token from the Authorization header
  # - Verifies the token signature and claims
  # - Checks that the session is still active (not revoked or expired)
  # - Emits authentication events for monitoring
  # - Handles authentication errors with JSON error responses
  #
  # @example Protecting an API endpoint
  #   class Api::UsersController < ApplicationController
  #     include TokenAuthority::TokenAuthentication
  #
  #     def show
  #       # token_user is the authenticated user
  #       # token_scope contains the granted scopes
  #       render json: token_user
  #     end
  #   end
  #
  # @since 0.2.0
  module TokenAuthentication
    extend ActiveSupport::Concern

    included do
      include TokenAuthority::ControllerEventLogging

      before_action :decode_token

      rescue_from TokenAuthority::MissingAuthorizationHeaderError, with: :missing_auth_header_response
      rescue_from TokenAuthority::InvalidAccessTokenError, with: :invalid_token_response
      rescue_from TokenAuthority::UnauthorizedAccessTokenError, with: :unauthorized_token_response
    end

    private

    # Extracts, decodes, and validates the JWT access token.
    #
    # Verifies that:
    # - An Authorization header is present
    # - The token can be decoded and has a valid signature
    # - A matching session exists and is still active
    # - The token passes all claim validations
    #
    # Sets @decoded_token instance variable on success.
    #
    # @return [void]
    #
    # @raise [TokenAuthority::MissingAuthorizationHeaderError] if no header present
    # @raise [TokenAuthority::InvalidAccessTokenError] if token is malformed
    # @raise [TokenAuthority::UnauthorizedAccessTokenError] if token is invalid or revoked
    # @api private
    def decode_token
      bearer_token_header = request.headers["AUTHORIZATION"]
      raise TokenAuthority::MissingAuthorizationHeaderError if bearer_token_header.blank?

      token = bearer_token_header.split.last
      access_token = TokenAuthority::AccessToken.from_token(token)

      oauth_session = TokenAuthority::Session.find_by(access_token_jti: access_token.jti)
      raise TokenAuthority::UnauthorizedAccessTokenError if oauth_session.blank?
      raise TokenAuthority::UnauthorizedAccessTokenError unless oauth_session.created_status?
      raise TokenAuthority::UnauthorizedAccessTokenError unless access_token.valid?

      @decoded_token = access_token

      notify_event("authentication.token.succeeded",
        session_id: oauth_session.id,
        scopes: access_token.scope)
    rescue JWT::DecodeError, ActiveModel::UnknownAttributeError
      raise TokenAuthority::InvalidAccessTokenError
    end

    # Returns the user associated with the authenticated token.
    #
    # @return [User] the user from the configured user_class
    # @api private
    def token_user
      @token_user ||= TokenAuthority.config.user_class.constantize.find(@decoded_token.user_id)
    end

    # Returns the scopes granted in the authenticated token.
    #
    # @return [Array<String>] the scope tokens
    # @api private
    def token_scope
      @token_scope ||= @decoded_token.scope&.split || []
    end

    # Renders error response for missing Authorization header.
    # @return [void]
    # @api private
    def missing_auth_header_response
      notify_event("authentication.token.failed",
        failure_reason: "missing_authorization_header")

      render json: {error: I18n.t("token_authority.errors.missing_auth_header")}, status: :unauthorized
    end

    # Renders error response for invalid token format.
    # @return [void]
    # @api private
    def invalid_token_response
      notify_event("authentication.token.failed",
        failure_reason: "invalid_token_format")

      render json: {error: I18n.t("token_authority.errors.invalid_token")}, status: :unauthorized
    end

    # Renders error response for unauthorized token.
    # @return [void]
    # @api private
    def unauthorized_token_response
      notify_event("authentication.token.failed",
        failure_reason: "unauthorized_token")

      render json: {error: I18n.t("token_authority.errors.unauthorized_token")}, status: :unauthorized
    end
  end
end
