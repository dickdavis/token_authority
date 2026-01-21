# frozen_string_literal: true

module TokenAuthority
  ##
  # Stores cached client metadata documents fetched from remote URIs
  class ClientMetadataDocumentCache < ApplicationRecord
    validates :uri_hash, presence: true, uniqueness: true
    validates :uri, presence: true
    validates :metadata, presence: true
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
  end
end
