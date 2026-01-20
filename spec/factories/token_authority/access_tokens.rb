# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_access_token, class: "TokenAuthority::AccessToken" do
    transient do
      token_authority_session { association(:token_authority_session) }
    end

    aud { TokenAuthority.config.rfc_9068_audience_url }
    exp { 5.minutes.from_now.to_i }
    iat { Time.zone.now.to_i }
    iss { TokenAuthority.config.rfc_9068_issuer_url }
    jti { token_authority_session.access_token_jti }
    user_id { token_authority_session.user_id }

    initialize_with { new(aud:, exp:, iat:, iss:, jti:, user_id:) }
  end
end
