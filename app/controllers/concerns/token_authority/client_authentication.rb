# frozen_string_literal: true

module TokenAuthority
  ##
  # Concern for authenticating OAuth clients via HTTP Basic Auth or public client ID.
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

      notify_event("authentication.client.failed",
        client_id: client_id,
        failure_reason: "missing_credentials",
        auth_method_attempted: "none")

      request_http_basic_authentication
    end

    def load_token_authority_client(id: nil)
      @token_authority_client = TokenAuthority::ClientIdResolver.resolve(id)
    rescue TokenAuthority::ClientNotFoundError
      @token_authority_client = nil
    end

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
