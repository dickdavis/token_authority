# frozen_string_literal: true

module TokenAuthority
  ##
  # Concern for authenticating OAuth clients via HTTP Basic Auth or public client ID.
  module ClientAuthentication
    extend ActiveSupport::Concern

    included do
      include ActionController::HttpAuthentication::Basic::ControllerMethods

      rescue_from TokenAuthority::ClientMismatchError, TokenAuthority::ClientNotFoundError do
        render plain: "HTTP Basic: Access denied.", status: :unauthorized
      end
    end

    private

    def authenticate_client(id: nil)
      client_id = id || params[:client_id]
      load_token_authority_client(id: client_id)
      return if @token_authority_client.present? && @token_authority_client.public_client_type?
      return if http_basic_auth_successful?

      request_http_basic_authentication
    end

    def load_token_authority_client(id: nil)
      @token_authority_client = TokenAuthority::Client.find_by(public_id: id)
    end

    def http_basic_auth_successful?
      authenticate_with_http_basic do |public_id, client_secret|
        @token_authority_client = TokenAuthority::Client.find_by(public_id:)
        raise TokenAuthority::ClientNotFoundError if @token_authority_client.blank?
        raise TokenAuthority::ClientMismatchError if params.key?(:client_id) && params[:client_id] != @token_authority_client.public_id

        @token_authority_client.authenticate_with_secret(client_secret)
      end
    end
  end
end
