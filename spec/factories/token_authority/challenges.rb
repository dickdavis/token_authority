# frozen_string_literal: true

FactoryBot.define do
  factory :token_authority_challenge, class: "TokenAuthority::Challenge" do
    code_challenge { Base64.urlsafe_encode64(Digest::SHA256.digest("code_verifier"), padding: false) }
    code_challenge_method { "S256" }
    redirect_uri { "http://localhost:3000/" }
    token_authority_authorization_grant
  end
end
