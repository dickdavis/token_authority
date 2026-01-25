# frozen_string_literal: true

module TokenAuthority
  ##
  # Service for fetching and caching JWKS from a remote URI using database storage
  class JwksFetcher
    extend TokenAuthority::Instrumentation

    class FetchError < StandardError; end

    class << self
      def fetch(uri)
        instrument("jwks.fetch", uri: uri) do |payload|
          cached = JwksCache.find_by_uri(uri)

          if cached && !cached.expired?
            payload[:cache_hit] = true
            return cached.to_jwk_set
          end

          payload[:cache_hit] = false

          # Fetch fresh data and update/create cache entry
          jwks_data = fetch_from_uri(uri)
          store_in_cache(uri, jwks_data)

          JWT::JWK::Set.new(jwks_data)
        end
      end

      def clear_cache(uri)
        JwksCache.find_by_uri(uri)&.destroy
      end

      def cleanup_expired!
        JwksCache.cleanup_expired!
      end

      private

      def fetch_from_uri(uri)
        parsed_uri = URI.parse(uri)
        raise FetchError, "Invalid URI scheme: #{uri}" unless parsed_uri.is_a?(URI::HTTPS)

        response = Net::HTTP.get_response(parsed_uri)
        raise FetchError, "HTTP #{response.code}: #{response.message}" unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body)
      rescue URI::InvalidURIError => e
        raise FetchError, "Invalid JWKS URI: #{e.message}"
      rescue JSON::ParserError => e
        raise FetchError, "Invalid JWKS JSON: #{e.message}"
      rescue => e
        raise FetchError, "Failed to fetch JWKS: #{e.message}"
      end

      def store_in_cache(uri, jwks_data)
        ttl = TokenAuthority.config.dcr_jwks_cache_ttl
        uri_hash = JwksCache.hash_uri(uri)

        JwksCache.find_or_initialize_by(uri_hash: uri_hash).tap do |cache|
          cache.uri = uri
          cache.jwks = jwks_data
          cache.expires_at = Time.current + ttl
          cache.save!
        end
      end
    end
  end
end
