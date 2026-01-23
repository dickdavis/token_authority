# frozen_string_literal: true

module TokenAuthority
  # Represents an OAuth 2.1 refresh token with JWT format.
  #
  # Refresh tokens are long-lived tokens used to obtain new access tokens without
  # requiring user interaction. Like access tokens, they follow JWT format but have
  # a longer expiration time (default: 14 days).
  #
  # Refresh tokens implement token rotation: each refresh operation creates a new
  # session with new access and refresh tokens, and marks the old session as
  # "refreshed". This prevents replay attacks.
  #
  # Unlike access tokens, refresh tokens do not include a user_id claim since they
  # are looked up by JTI in the Session table which already has the user association.
  #
  # This is an ActiveModel object (not ActiveRecord) that provides validation
  # and serialization of JWT claims without database persistence.
  #
  # @example Creating a refresh token
  #   token = TokenAuthority::RefreshToken.default(
  #     exp: 14.days.from_now,
  #     resources: ["https://api.example.com"],
  #     scopes: ["read", "write"]
  #   )
  #   jwt_string = token.to_encoded_token
  #
  # @example Decoding a refresh token
  #   token = TokenAuthority::RefreshToken.from_token(jwt_string)
  #   token.valid? # => true/false
  #
  # @since 0.2.0
  class RefreshToken
    include TokenAuthority::ClaimValidatable

    # @!attribute [rw] scope
    #   Space-separated list of OAuth scopes for this refresh token.
    #   @return [String, nil]
    attr_accessor :scope

    # Creates a new refresh token with standard JWT claims.
    #
    # The audience (aud) claim is set from resource indicators if provided,
    # otherwise falls back to the configured default audience URL.
    #
    # @param exp [Time, Integer] token expiration time
    # @param resources [Array<String>] resource indicators (RFC 8707)
    # @param scopes [Array<String>] OAuth scopes to include
    #
    # @return [TokenAuthority::RefreshToken] the new token instance
    #
    # @example
    #   token = RefreshToken.default(
    #     exp: 14.days.from_now,
    #     resources: ["https://api.example.com"],
    #     scopes: ["read", "write"]
    #   )
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

    # Decodes a JWT string into a RefreshToken instance.
    #
    # @param token [String] the JWT-encoded refresh token
    #
    # @return [TokenAuthority::RefreshToken] the decoded token instance
    #
    # @raise [JWT::DecodeError] if the token is malformed or signature is invalid
    #
    # @example
    #   token = RefreshToken.from_token(jwt_string)
    #   jti = token.jti
    def self.from_token(token)
      new(TokenAuthority::JsonWebToken.decode(token))
    end

    # Converts the token to a hash of JWT claims.
    #
    # Nil values are omitted from the hash to produce a minimal JWT payload.
    #
    # @return [Hash] the JWT claims
    def to_h
      {aud:, exp:, iat:, iss:, jti:, scope:}.compact
    end

    # Encodes the token as a signed JWT string.
    #
    # @return [String] the JWT-encoded refresh token
    def to_encoded_token
      TokenAuthority::JsonWebToken.encode(to_h, exp)
    end
  end
end
