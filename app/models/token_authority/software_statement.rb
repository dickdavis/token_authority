# frozen_string_literal: true

module TokenAuthority
  ##
  # Value object for parsing and validating software statements (signed JWT metadata)
  class SoftwareStatement
    STANDARD_CLAIMS = %i[
      redirect_uris
      token_endpoint_auth_method
      grant_types
      response_types
      client_name
      client_uri
      logo_uri
      scope
      contacts
      tos_uri
      policy_uri
      jwks_uri
      jwks
      software_id
      software_version
    ].freeze

    attr_reader :raw_jwt, :payload, :header

    def initialize(raw_jwt:, payload:, header:, verified: false)
      @raw_jwt = raw_jwt
      @payload = payload.with_indifferent_access
      @header = header.with_indifferent_access
      @verified = verified
    end

    class << self
      def decode(jwt)
        payload, header = JWT.decode(jwt, nil, false)
        new(raw_jwt: jwt, payload: payload, header: header, verified: false)
      rescue JWT::DecodeError => e
        raise TokenAuthority::InvalidSoftwareStatementError, e.message
      end

      def decode_and_verify(jwt, jwks:)
        jwk_set = jwks.is_a?(JWT::JWK::Set) ? jwks : JWT::JWK::Set.new(jwks)
        algorithms = jwk_set.map { |key| key[:alg] }.compact.uniq
        algorithms = ["RS256"] if algorithms.empty?

        payload, header = JWT.decode(jwt, nil, true, {algorithms: algorithms, jwks: jwk_set})
        new(raw_jwt: jwt, payload: payload, header: header, verified: true)
      rescue JWT::DecodeError => e
        raise TokenAuthority::InvalidSoftwareStatementError, e.message
      end
    end

    STANDARD_CLAIMS.each do |claim|
      define_method(claim) { payload[claim] }
    end

    def claims
      payload.slice(*STANDARD_CLAIMS)
    end

    def trusted?
      @verified
    end

    def to_h
      claims
    end
  end
end
