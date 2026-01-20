# frozen_string_literal: true

module TokenAuthority
  ##
  # Models an access token
  class AccessToken
    include TokenAuthority::ClaimValidatable

    attr_accessor :user_id

    validates :user_id, presence: true, comparison: {equal_to: :user_id_from_token_authority_session}

    def self.default(exp:, user_id:)
      new(
        aud: TokenAuthority.config.audience_url,
        exp:,
        iat: Time.zone.now.to_i,
        iss: TokenAuthority.config.issuer_url,
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
