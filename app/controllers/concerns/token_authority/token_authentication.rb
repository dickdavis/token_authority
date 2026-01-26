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
      @token_user ||= TokenAuthority.config.user_class.constantize.find(@decoded_token.sub)
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

      set_www_authenticate_header
      render json: {error: I18n.t("token_authority.errors.missing_auth_header")}, status: :unauthorized
    end

    # Renders error response for invalid token format.
    # @return [void]
    # @api private
    def invalid_token_response
      notify_event("authentication.token.failed",
        failure_reason: "invalid_token_format")

      set_www_authenticate_header(error: "invalid_token")
      render json: {error: I18n.t("token_authority.errors.invalid_token")}, status: :unauthorized
    end

    # Renders error response for unauthorized token.
    # @return [void]
    # @api private
    def unauthorized_token_response
      notify_event("authentication.token.failed",
        failure_reason: "unauthorized_token")

      set_www_authenticate_header(error: "invalid_token")
      render json: {error: I18n.t("token_authority.errors.unauthorized_token")}, status: :unauthorized
    end

    # Sets the WWW-Authenticate header for 401 responses per RFC 9728 and MCP spec.
    #
    # This header tells OAuth clients where to find the protected resource
    # metadata, enabling automatic OAuth flow discovery (including DCR).
    #
    # Per MCP Authorization spec, the header SHOULD include a scope parameter
    # to indicate scopes required for accessing the resource (RFC 6750 Section 3).
    #
    # @param error [String, nil] optional OAuth error code (e.g., "invalid_token")
    # @return [void]
    # @api private
    def set_www_authenticate_header(error: nil)
      resource_config = current_protected_resource_config
      metadata_url = protected_resource_metadata_url(resource_config)
      return if metadata_url.blank?

      header_value = %(Bearer resource_metadata="#{metadata_url}")
      header_value += %(, scope="#{www_authenticate_scope(resource_config)}") if www_authenticate_scope(resource_config).present?
      header_value += %(, error="#{error}") if error.present?

      response.headers["WWW-Authenticate"] = header_value
    end

    # Returns the current protected resource configuration.
    #
    # Looks up the resource by request subdomain. If no subdomain match is found,
    # the first configured resource is used.
    #
    # @return [Hash, nil] the resource configuration
    # @api private
    def current_protected_resource_config
      subdomain = request.subdomain.presence
      TokenAuthority.config.protected_resource_for(subdomain)
    end

    # Returns the URL for the protected resource metadata endpoint.
    #
    # Derives the URL from the resource configuration's :resource field,
    # which represents the protected resource URI. The well-known path is
    # appended to form the complete metadata URL.
    #
    # If no resources are configured, falls back to deriving from the current
    # request host.
    #
    # Controllers can override this method to customize the metadata URL.
    #
    # @param resource_config [Hash, nil] the resource configuration
    # @return [String] the metadata URL
    # @api private
    def protected_resource_metadata_url(resource_config = nil)
      resource_config ||= current_protected_resource_config

      if resource_config.is_a?(Hash) && resource_config[:resource].present?
        resource_uri = URI(resource_config[:resource])
        return "#{resource_uri.scheme}://#{resource_uri.host}/.well-known/oauth-protected-resource"
      end

      # Fallback: derive from request origin
      "#{request.protocol}#{request.host_with_port}/.well-known/oauth-protected-resource"
    end

    # Returns the scope value for the WWW-Authenticate header.
    #
    # Uses the resource's scopes_supported configuration to indicate what
    # scopes are required for accessing this resource. Per MCP spec, this
    # provides clients with guidance on appropriate scopes to request.
    #
    # Controllers can override this method to specify different scopes
    # (e.g., endpoint-specific required scopes).
    #
    # @param resource_config [Hash, nil] the resource configuration
    # @return [String, nil] space-separated scope string, or nil if no scopes configured
    # @api private
    def www_authenticate_scope(resource_config = nil)
      resource_config ||= current_protected_resource_config
      return nil unless resource_config.is_a?(Hash)

      scopes = resource_config[:scopes_supported]
      return nil unless scopes.is_a?(Array) && scopes.any?

      scopes.join(" ")
    end
  end
end
