# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_access_token, class: "TokenAuthority::AccessToken" do
    transient do
      token_authority_session { association(:token_authority_session) }
    end

    aud { TokenAuthority.config.audience_url }
    exp { 5.minutes.from_now.to_i }
    iat { Time.zone.now.to_i }
    iss { TokenAuthority.config.issuer_url }
    jti { token_authority_session.access_token_jti }
    sub { token_authority_session.user_id.to_s }
    client_id { token_authority_session.token_authority_authorization_grant&.resolved_client&.public_id || "test-client-id" }
    scope { nil }

    initialize_with { new(aud:, exp:, iat:, iss:, jti:, sub:, client_id:, scope:) }
  end
end
