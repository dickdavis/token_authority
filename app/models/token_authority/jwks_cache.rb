# frozen_string_literal: true

module TokenAuthority
  ##
  # Stores cached JWKS fetched from remote URIs
  class JwksCache < ApplicationRecord
    validates :uri_hash, presence: true, uniqueness: true
    validates :uri, presence: true
    validates :jwks, presence: true
    validates :expires_at, presence: true

    scope :expired, -> { where("expires_at <= ?", Time.current) }
    scope :valid, -> { where("expires_at > ?", Time.current) }

    class << self
      def find_by_uri(uri)
        find_by(uri_hash: hash_uri(uri))
      end

      def hash_uri(uri)
        Digest::SHA256.hexdigest(uri)
      end

      def cleanup_expired!
        expired.delete_all
      end
    end

    def expired?
      expires_at <= Time.current
    end

    def to_jwk_set
      JWT::JWK::Set.new(jwks)
    end
  end
end
