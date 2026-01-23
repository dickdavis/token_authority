# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a refresh token
  class RefreshToken
    include TokenAuthority::ClaimValidatable

    attr_accessor :scope

    def self.default(exp:, resources: [], scopes: [])
      # Use resources for aud claim if provided, otherwise fall back to config
      aud = if resources.any?
        (resources.size == 1) ? resources.first : resources
      else
        TokenAuthority.config.rfc_9068_audience_url
      end

      # Only include scope if scopes are provided
      scope_claim = scopes.any? ? scopes.join(" ") : nil

      new(
        aud:,
        exp:,
        iat: Time.zone.now.to_i,
        iss: TokenAuthority.config.rfc_9068_issuer_url,
        jti: SecureRandom.uuid,
        scope: scope_claim
      )
    end

    def self.from_token(token)
      new(TokenAuthority::JsonWebToken.decode(token))
    end

    def to_h
      {aud:, exp:, iat:, iss:, jti:, scope:}.compact
    end

    def to_encoded_token
      TokenAuthority::JsonWebToken.encode(to_h, exp)
    end
  end
end
