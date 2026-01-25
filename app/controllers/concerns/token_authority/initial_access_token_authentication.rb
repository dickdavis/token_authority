# frozen_string_literal: true

module TokenAuthority
  ##
  # Concern for authenticating initial access tokens in protected registration mode
  module InitialAccessTokenAuthentication
    extend ActiveSupport::Concern

    included do
      before_action :authenticate_initial_access_token, if: :initial_access_token_required?
    end

    private

    def initial_access_token_required?
      TokenAuthority.config.dcr_require_initial_access_token
    end

    def authenticate_initial_access_token
      token = extract_bearer_token
      raise TokenAuthority::InvalidInitialAccessTokenError if token.blank?

      validator = TokenAuthority.config.dcr_initial_access_token_validator
      raise TokenAuthority::InvalidInitialAccessTokenError unless validator&.call(token)
    end

    def extract_bearer_token
      auth_header = request.headers["Authorization"]
      return nil if auth_header.blank?

      match = auth_header.match(/\ABearer\s+(.+)\z/i)
      match&.captures&.first
    end
  end
end
