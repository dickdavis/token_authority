# frozen_string_literal: true

require "jwt"

module TokenAuthority
  # Provides JWT encoding and decoding functionality for TokenAuthority.
  #
  # This module wraps the ruby-jwt gem and adds instrumentation for monitoring.
  # All JWTs are signed using HMAC-SHA256 with the configured secret key.
  #
  # Token expiration validation is disabled during decoding to allow the application
  # to handle expired tokens gracefully and provide better error messages.
  #
  # @note This module uses ActiveSupport::Notifications for instrumentation when enabled.
  #
  # @example Encoding a token
  #   payload = { user_id: 123, scope: "read write" }
  #   token = TokenAuthority::JsonWebToken.encode(payload, 1.hour.from_now)
  #
  # @example Decoding a token
  #   payload = TokenAuthority::JsonWebToken.decode(token)
  #   user_id = payload[:user_id]
  #
  # @since 0.2.0
  module JsonWebToken
    extend TokenAuthority::Instrumentation

    # Encodes a payload into a signed JWT.
    #
    # The expiration time is added to the payload before encoding.
    # Emits an instrumentation event with the token size.
    #
    # @param payload [Hash] the JWT claims to encode
    # @param expiration [Time, ActiveSupport::TimeWithZone] when the token expires
    #   (default: 30 minutes from now)
    #
    # @return [String] the encoded JWT token
    #
    # @example
    #   token = JsonWebToken.encode({ user_id: 42 }, 1.hour.from_now)
    def self.encode(payload, expiration = 30.minutes.from_now)
      payload[:exp] = expiration.to_i

      instrument("jwt.encode") do |p|
        token = JWT.encode(payload, TokenAuthority.config.secret_key)
        p[:token_size] = token.bytesize
        token
      end
    end

    # Decodes and verifies a JWT signature.
    #
    # Expiration validation is intentionally disabled to allow the application
    # to handle expired tokens with custom error messages and logic.
    # Emits an instrumentation event with the token size.
    #
    # @param token [String] the JWT token to decode
    #
    # @return [ActiveSupport::HashWithIndifferentAccess] the decoded JWT claims
    #
    # @raise [JWT::DecodeError] if the token is malformed or signature is invalid
    #
    # @example
    #   payload = JsonWebToken.decode(token_string)
    #   user_id = payload[:user_id]
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
