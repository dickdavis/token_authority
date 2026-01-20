# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_access_token_request, class: "TokenAuthority::AccessTokenRequest" do
    code_verifier { "code_verifier" }
    redirect_uri { "http://localhost:3000/" }
    token_authority_authorization_grant
  end
end
