# frozen_string_literal: true

require "jwt"

module TokenAuthority
  ##
  # Module for encoding and decoding JWTs.
  module JsonWebToken
    extend TokenAuthority::Instrumentation

    def self.encode(payload, expiration = 30.minutes.from_now)
      payload[:exp] = expiration.to_i

      instrument("jwt.encode") do |p|
        token = JWT.encode(payload, TokenAuthority.config.secret_key)
        p[:token_size] = token.bytesize
        token
      end
    end

    def self.decode(token)
      instrument("jwt.decode", token_size: token.bytesize) do
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
end
