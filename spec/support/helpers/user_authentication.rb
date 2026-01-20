# frozen_string_literal: true

##
# Provides helper for user authentication in request specs
module UserAuthentication
  def sign_in(user)
    post sign_in_path, params: {email: user.email, password: "password123"}
  end
end

RSpec.configure do |config|
  config.include UserAuthentication, type: :request
end
