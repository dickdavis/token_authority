# frozen_string_literal: true

##
# Factory for TokenAuthority::Client model
FactoryBot.define do
  factory :token_authority_client, class: "TokenAuthority::Client" do
    name { "Demo Client" }
    client_type { "confidential" }
    redirect_uri { "http://localhost:3000/" }
    access_token_duration { 300 }
    refresh_token_duration { 1_209_600 }
  end
end
