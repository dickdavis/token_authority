# frozen_string_literal: true

require "jwt"

module TokenAuthority
  ##
  # Module for encoding and decoding JWTs.
  module JsonWebToken
    def self.encode(payload, expiration = 30.minutes.from_now)
      payload[:exp] = expiration.to_i
      JWT.encode(payload, TokenAuthority.config.secret_key)
    end

    def self.decode(token)
      (payload,) = JWT.decode(
        token,
        TokenAuthority.config.secret_key,
        true,
        {verify_expiration: false, algorithm: "HS256"}
      )
      ActiveSupport::HashWithIndifferentAccess.new(payload)
    end
  end
end
