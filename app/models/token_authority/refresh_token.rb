# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a refresh token
  class RefreshToken
    include TokenAuthority::ClaimValidatable

    def self.default(exp:, resources: [])
      # Use resources for aud claim if provided, otherwise fall back to config
      aud = if resources.any?
        (resources.size == 1) ? resources.first : resources
      else
        TokenAuthority.config.rfc_9068_audience_url
      end

      new(
        aud:,
        exp:,
        iat: Time.zone.now.to_i,
        iss: TokenAuthority.config.rfc_9068_issuer_url,
        jti: SecureRandom.uuid
      )
    end

    def self.from_token(token)
      new(TokenAuthority::JsonWebToken.decode(token))
    end

    def to_h
      {aud:, exp:, iat:, iss:, jti:}
    end

    def to_encoded_token
      TokenAuthority::JsonWebToken.encode(to_h, exp)
    end
  end
end
