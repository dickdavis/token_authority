# frozen_string_literal: true

module TokenAuthority
  # Represents an OAuth 2.1 access token with JWT format per RFC 9068.
  #
  # Access tokens are short-lived bearer tokens that grant access to protected
  # resources. They are not persisted in the database; instead, only their JTI
  # (JWT ID) is stored in the Session model for revocation lookups.
  #
  # The tokens follow RFC 9068 JWT Profile for OAuth Access Tokens, including
  # standard claims (iss, sub, aud, exp, iat, jti, client_id) plus the scope claim.
  #
  # This is an ActiveModel object (not ActiveRecord) that provides validation
  # and serialization of JWT claims without database persistence.
  #
  # @example Creating a new access token
  #   token = TokenAuthority::AccessToken.default(
  #     exp: 5.minutes.from_now,
  #     user_id: 42,
  #     client_id: "550e8400-e29b-41d4-a716-446655440000",
  #     resources: ["https://api.example.com"],
  #     scopes: ["read", "write"]
  #   )
  #   jwt_string = token.to_encoded_token
  #
  # @example Decoding and validating a token
  #   token = TokenAuthority::AccessToken.from_token(jwt_string)
  #   token.valid? # => true/false
  #
  # @since 0.2.0
  class AccessToken
    include TokenAuthority::ClaimValidatable

    # @!attribute [rw] sub
    #   The subject identifier (resource owner) per RFC 9068.
    #   @return [String]
    attr_accessor :sub

    # @!attribute [rw] client_id
    #   The OAuth client identifier per RFC 9068/RFC 8693.
    #   @return [String]
    attr_accessor :client_id

    # @!attribute [rw] scope
    #   Space-separated list of OAuth scopes granted to this token.
    #   @return [String, nil]
    attr_accessor :scope

    validates :sub, presence: true, comparison: {equal_to: :sub_from_token_authority_session}

    # Creates a new access token with default claims per RFC 9068.
    #
    # The audience (aud) claim is set from resource indicators if provided,
    # otherwise falls back to the configured default audience URL.
    #
    # @param exp [Time, Integer] token expiration time
    # @param user_id [Integer] the user ID (converted to string for sub claim)
    # @param client_id [String] the OAuth client identifier
    # @param resources [Array<String>] resource indicators (RFC 8707)
    # @param scopes [Array<String>] OAuth scopes to include
    #
    # @return [TokenAuthority::AccessToken] the new token instance
    #
    # @example
    #   token = AccessToken.default(
    #     exp: 5.minutes.from_now,
    #     user_id: 123,
    #     client_id: "550e8400-e29b-41d4-a716-446655440000",
    #     resources: ["https://api.example.com"],
    #     scopes: ["read", "write"]
    #   )
    def self.default(exp:, user_id:, client_id:, resources: [], scopes: [])
      # Use resources for aud claim if provided, otherwise fall back to config
      aud = if resources.any?
        (resources.size == 1) ? resources.first : resources
      else
        TokenAuthority.config.rfc_9068_audience_url
      end

      scope_claim = scopes.any? ? scopes.join(" ") : nil

      new(
        aud:,
        exp:,
        iat: Time.zone.now.to_i,
        iss: TokenAuthority.config.rfc_9068_issuer_url,
        jti: SecureRandom.uuid,
        sub: user_id.to_s,
        client_id:,
        scope: scope_claim
      )
    end

    # Decodes a JWT string into an AccessToken instance.
    #
    # @param token [String] the JWT-encoded access token
    #
    # @return [TokenAuthority::AccessToken] the decoded token instance
    #
    # @raise [JWT::DecodeError] if the token is malformed or signature is invalid
    #
    # @example
    #   token = AccessToken.from_token(jwt_string)
    #   subject = token.sub
    def self.from_token(token)
      new(TokenAuthority::JsonWebToken.decode(token))
    end

    # Converts the token to a hash of JWT claims.
    #
    # Nil values are omitted from the hash to produce a minimal JWT payload.
    #
    # @return [Hash] the JWT claims
    def to_h
      {aud:, exp:, iat:, iss:, jti:, sub:, client_id:, scope:}.compact
    end

    # Encodes the token as a signed JWT string.
    #
    # @return [String] the JWT-encoded access token
    def to_encoded_token
      TokenAuthority::JsonWebToken.encode(to_h, exp)
    end

    private

    # Returns the subject (user_id as string) from the associated session for validation.
    #
    # @return [String, nil]
    # @api private
    def sub_from_token_authority_session
      token_authority_session&.user_id&.to_s
    end
  end
end
