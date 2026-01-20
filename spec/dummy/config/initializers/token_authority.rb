# frozen_string_literal: true

TokenAuthority.configure do |config|
  config.audience_url = "http://localhost:3000/api/"
  config.issuer_url = "http://localhost:3000/"
  config.secret_key = "test_secret_key_for_token_authority"
  config.user_class = "User"
end
