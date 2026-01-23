# frozen_string_literal: true

module TokenAuthority
  ##
  # Provides support for creating token authority sessions
  module SessionCreatable
    extend ActiveSupport::Concern

    TokenContainer = Data.define(:access_token, :refresh_token, :expiration)

    private

    def create_token_authority_session(grant:, resources: [])
      client = grant.resolved_client
      access_token_expiration = client.access_token_duration.seconds.from_now.to_i
      access_token = TokenAuthority::AccessToken.default(user_id:, exp: access_token_expiration, resources:)

      refresh_token_expiration = client.refresh_token_duration.seconds.from_now.to_i
      refresh_token = TokenAuthority::RefreshToken.default(exp: refresh_token_expiration, resources:)

      token_authority_session = grant.token_authority_sessions.new(
        access_token_jti: access_token.jti, refresh_token_jti: refresh_token.jti
      )

      if token_authority_session.save
        yield
        TokenContainer[access_token.to_encoded_token, refresh_token.to_encoded_token, access_token.exp]
      else
        errors = token_authority_session.errors.full_messages.join(", ")
        raise TokenAuthority::ServerError, I18n.t("token_authority.errors.oauth_session_failure", errors:)
      end
    end
  end
end
