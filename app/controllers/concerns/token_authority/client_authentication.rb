# frozen_string_literal: true

module TokenAuthority
  # Provides OAuth client authentication for controllers.
  #
  # This concern handles authentication of OAuth clients during authorization
  # and token requests. It supports multiple authentication methods:
  # - Public clients (using only client_id, no secret required)
  # - HTTP Basic authentication (client_secret_basic)
  # - POST body credentials (client_secret_post)
  #
  # The concern automatically:
  # - Resolves client_id to either a registered Client or URL-based ClientMetadataDocument
  # - Validates credentials via HTTP Basic or POST body for confidential clients
  # - Emits authentication events for monitoring and security auditing
  # - Handles authentication errors with appropriate HTTP responses
  #
  # @example Using in a controller
  #   class MyController < ApplicationController
  #     include TokenAuthority::ClientAuthentication
  #
  #     before_action :authenticate_client
  #
  #     def my_action
  #       # @token_authority_client is now available
  #     end
  #   end
  #
  # @since 0.2.0
  module ClientAuthentication
    extend ActiveSupport::Concern

    included do
      include ActionController::HttpAuthentication::Basic::ControllerMethods
      include TokenAuthority::ControllerEventLogging

      rescue_from TokenAuthority::ClientMismatchError do
        notify_event("authentication.client.failed",
          client_id: params[:client_id],
          failure_reason: "client_mismatch",
          auth_method_attempted: "http_basic")

        render plain: "HTTP Basic: Access denied.", status: :unauthorized
      end

      rescue_from TokenAuthority::ClientNotFoundError do
        notify_event("authentication.client.failed",
          client_id: params[:client_id],
          failure_reason: "client_not_found",
          auth_method_attempted: "http_basic")

        render plain: "HTTP Basic: Access denied.", status: :unauthorized
      end
    end

    private

    # Authenticates an OAuth client.
    #
    # Public clients are authenticated by client_id alone. Confidential clients
    # must provide valid credentials via HTTP Basic authentication.
    #
    # Sets @token_authority_client instance variable on successful authentication.
    #
    # @param id [String, nil] the client_id (uses params[:client_id] if not provided)
    #
    # @return [void]
    #
    # @raise [TokenAuthority::ClientMismatchError] if HTTP Basic credentials don't match params
    # @raise [TokenAuthority::ClientNotFoundError] if client cannot be found
    #
    # @api private
    def authenticate_client(id: nil)
      client_id = id || params[:client_id]
      load_token_authority_client(id: client_id)

      if @token_authority_client.present? && @token_authority_client.public_client_type?
        notify_event("authentication.client.succeeded",
          client_id: @token_authority_client.public_id,
          client_type: @token_authority_client.client_type,
          auth_method: "public_client")
        return
      end

      if http_basic_auth_successful?
        notify_event("authentication.client.succeeded",
          client_id: @token_authority_client.public_id,
          client_type: @token_authority_client.client_type,
          auth_method: "http_basic")
        return
      end

      if client_secret_post_auth_successful?
        notify_event("authentication.client.succeeded",
          client_id: @token_authority_client.public_id,
          client_type: @token_authority_client.client_type,
          auth_method: "client_secret_post")
        return
      end

      notify_event("authentication.client.failed",
        client_id: client_id,
        failure_reason: "missing_credentials",
        auth_method_attempted: "none")

      request_http_basic_authentication
    end

    # Loads the client by ID using the ClientIdResolver.
    #
    # Sets @token_authority_client to nil if client is not found.
    #
    # @param id [String, nil] the client identifier
    #
    # @return [void]
    # @api private
    def load_token_authority_client(id: nil)
      @token_authority_client = TokenAuthority::ClientIdResolver.resolve(id)
    rescue TokenAuthority::ClientNotFoundError
      @token_authority_client = nil
    end

    # Attempts to authenticate using client_secret_post (credentials in POST body).
    #
    # Validates the client_secret from POST parameters against the loaded client.
    # Accepts POST body credentials for confidential clients configured with either
    # client_secret_post or client_secret_basic auth methods.
    #
    # @return [Boolean] true if authentication succeeds
    # @api private
    def client_secret_post_auth_successful?
      return false if params[:client_secret].blank?
      return false if @token_authority_client.blank?
      return false if @token_authority_client.public_client_type?

      authenticated = @token_authority_client.authenticate_with_secret(params[:client_secret])
      unless authenticated
        notify_event("authentication.client.failed",
          client_id: @token_authority_client.public_id,
          failure_reason: "invalid_secret",
          auth_method_attempted: "client_secret_post")
      end
      authenticated
    end

    # Attempts to authenticate using HTTP Basic credentials.
    #
    # Verifies that the client_id in Basic auth matches params[:client_id] if present,
    # and validates the client_secret.
    #
    # @return [Boolean] true if authentication succeeds
    #
    # @raise [TokenAuthority::ClientMismatchError] if IDs don't match
    # @raise [TokenAuthority::ClientNotFoundError] if client not found
    # @api private
    def http_basic_auth_successful?
      authenticate_with_http_basic do |public_id, client_secret|
        @token_authority_client = TokenAuthority::Client.find_by(public_id:)
        raise TokenAuthority::ClientNotFoundError if @token_authority_client.blank?
        raise TokenAuthority::ClientMismatchError if params.key?(:client_id) && params[:client_id] != @token_authority_client.public_id

        authenticated = @token_authority_client.authenticate_with_secret(client_secret)
        unless authenticated
          notify_event("authentication.client.failed",
            client_id: public_id,
            failure_reason: "invalid_secret",
            auth_method_attempted: "http_basic")
        end
        authenticated
      end
    end
  end
end
