# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_refresh_token_request, class: "TokenAuthority::RefreshTokenRequest" do
    transient do
      token_authority_session { association(:token_authority_session) }
    end

    token { build(:token_authority_refresh_token, token_authority_session:) }
    resources { nil }
    client_id { nil }
  end
end
