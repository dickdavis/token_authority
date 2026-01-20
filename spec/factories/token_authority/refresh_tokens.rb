# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_refresh_token, class: "TokenAuthority::RefreshToken" do
    transient do
      token_authority_session { association(:token_authority_session) }
    end

    aud { TokenAuthority.config.audience_url }
    exp { 14.days.from_now.to_i }
    iat { Time.zone.now.to_i }
    iss { TokenAuthority.config.issuer_url }
    jti { token_authority_session.refresh_token_jti }

    initialize_with { new(aud:, exp:, iat:, iss:, jti:) }
  end
end
