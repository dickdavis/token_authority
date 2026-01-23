# frozen_string_literal: true

module TokenAuthority
  ##
  # Models an access token
  class AccessToken
    include TokenAuthority::ClaimValidatable

    attr_accessor :user_id

    validates :user_id, presence: true, comparison: {equal_to: :user_id_from_token_authority_session}

    def self.default(exp:, user_id:, resources: [])
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
        jti: SecureRandom.uuid,
        user_id:
      )
    end

    def self.from_token(token)
      new(TokenAuthority::JsonWebToken.decode(token))
    end

    def to_h
      {aud:, exp:, iat:, iss:, jti:, user_id:}
    end

    def to_encoded_token
      TokenAuthority::JsonWebToken.encode(to_h, exp)
    end

    private

    def user_id_from_token_authority_session
      token_authority_session&.user_id
    end
  end
end
