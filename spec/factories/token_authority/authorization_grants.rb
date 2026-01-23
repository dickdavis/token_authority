# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_authorization_grant, class: "TokenAuthority::AuthorizationGrant" do
    expires_at { 9.minutes.from_now }
    redeemed { false }
    user
    token_authority_client

    code_challenge do
      Base64.urlsafe_encode64(
        Digest::SHA256.digest("code_verifier"), padding: false
      )
    end
    code_challenge_method { "S256" }
    redirect_uri { "http://localhost:3000/" }
    resources { [] }
    scopes { [] }
  end
end
