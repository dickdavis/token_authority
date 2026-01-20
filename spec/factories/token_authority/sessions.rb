# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_session, class: "TokenAuthority::Session" do
    access_token_jti { SecureRandom.uuid }
    refresh_token_jti { SecureRandom.uuid }
    status { "created" }
    token_authority_authorization_grant
  end
end
