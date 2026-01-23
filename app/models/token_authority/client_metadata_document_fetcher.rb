# frozen_string_literal: true

require "net/http"
require "resolv"
require "ipaddr"

module TokenAuthority
  ##
  # Service for fetching and caching client metadata documents from remote URIs
  class ClientMetadataDocumentFetcher
    extend TokenAuthority::Instrumentation
    include TokenAuthority::EventLogging

    # Private IP ranges for SSRF protection
    PRIVATE_IP_RANGES = [
      IPAddr.new("10.0.0.0/8"),
      IPAddr.new("172.16.0.0/12"),
      IPAddr.new("192.168.0.0/16"),
      IPAddr.new("127.0.0.0/8"),
      IPAddr.new("169.254.0.0/16"),  # Link-local
      IPAddr.new("0.0.0.0/8"),
      IPAddr.new("::1/128"),          # IPv6 localhost
      IPAddr.new("fc00::/7"),         # IPv6 unique local
      IPAddr.new("fe80::/10")         # IPv6 link-local
    ].freeze

    class << self
      def fetch(uri)
        instrument("client_metadata.fetch", uri: uri) do |payload|
          validate_url!(uri)

          cached = ClientMetadataDocumentCache.find_by_uri(uri)

          if cached && !cached.expired?
            debug_event("client.metadata.cache_hit", uri: uri, expires_at: cached.expires_at&.iso8601)
            payload[:cache_hit] = true
            return cached.metadata
          end

          debug_event("client.metadata.cache_miss", uri: uri)
          payload[:cache_hit] = false

          # Fetch fresh data and update/create cache entry
          metadata = fetch_from_uri(uri)
          validate_metadata!(uri, metadata)
          store_in_cache(uri, metadata)

          debug_event("client.metadata.fetched", uri: uri, client_name: metadata["client_name"])

          metadata
        end
      end

      def clear_cache(uri)
        ClientMetadataDocumentCache.find_by_uri(uri)&.destroy
      end

      def cleanup_expired!
        ClientMetadataDocumentCache.cleanup_expired!
      end

      def valid_client_id_url?(url)
        validate_url!(url)
        true
      rescue InvalidClientMetadataDocumentUrlError
        false
      end

      private

      def validate_url!(url)
        parsed_uri = URI.parse(url)

        # Must be HTTPS
        unless parsed_uri.is_a?(URI::HTTPS)
          raise InvalidClientMetadataDocumentUrlError, "Client ID URL must use HTTPS scheme"
        end

        # Must have a path (not just "/")
        if parsed_uri.path.blank? || parsed_uri.path == "/"
          raise InvalidClientMetadataDocumentUrlError, "Client ID URL must have a path"
        end

        # Must not have a fragment
        if parsed_uri.fragment.present?
          raise InvalidClientMetadataDocumentUrlError, "Client ID URL must not have a fragment"
        end

        # Must not have user credentials
        if parsed_uri.user.present? || parsed_uri.password.present?
          raise InvalidClientMetadataDocumentUrlError, "Client ID URL must not have credentials"
        end

        # Check host against allow/block lists
        validate_host!(parsed_uri.host)

        true
      rescue URI::InvalidURIError => e
        raise InvalidClientMetadataDocumentUrlError, "Invalid URI: #{e.message}"
      end

      def validate_host!(host)
        config = TokenAuthority.config

        # Check blocked hosts
        if config.client_metadata_document_blocked_hosts&.any? { |pattern| host_matches?(host, pattern) }
          raise InvalidClientMetadataDocumentUrlError, "Host is blocked: #{host}"
        end

        # Check allowed hosts (if configured)
        if config.client_metadata_document_allowed_hosts.present?
          unless config.client_metadata_document_allowed_hosts.any? { |pattern| host_matches?(host, pattern) }
            raise InvalidClientMetadataDocumentUrlError, "Host is not in allowed list: #{host}"
          end
        end

        true
      end

      def host_matches?(host, pattern)
        if pattern.start_with?("*.")
          # Wildcard pattern: *.example.com matches foo.example.com
          suffix = pattern[1..]
          host.end_with?(suffix) || host == pattern[2..]
        else
          host == pattern
        end
      end

      def fetch_from_uri(uri)
        parsed_uri = URI.parse(uri)
        config = TokenAuthority.config

        # Resolve DNS and validate IP before connecting (SSRF protection)
        resolved_ip = resolve_and_validate_ip(parsed_uri.host)

        http = Net::HTTP.new(parsed_uri.host, parsed_uri.port)
        http.use_ssl = true
        http.open_timeout = config.client_metadata_document_connect_timeout
        http.read_timeout = config.client_metadata_document_read_timeout
        http.ipaddr = resolved_ip # Use resolved IP to prevent DNS rebinding

        request = Net::HTTP::Get.new(parsed_uri.request_uri)
        request["Accept"] = "application/json"

        response = http.request(request)

        unless response.is_a?(Net::HTTPSuccess)
          raise ClientMetadataDocumentFetchError, "HTTP #{response.code}: #{response.message}"
        end

        # Check response size
        max_size = config.client_metadata_document_max_response_size
        if response.body.bytesize > max_size
          raise ClientMetadataDocumentFetchError, "Response exceeds maximum size of #{max_size} bytes"
        end

        JSON.parse(response.body)
      rescue URI::InvalidURIError => e
        raise ClientMetadataDocumentFetchError, "Invalid URI: #{e.message}"
      rescue JSON::ParserError => e
        raise ClientMetadataDocumentFetchError, "Invalid JSON: #{e.message}"
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::ENETUNREACH,
        Net::OpenTimeout, Net::ReadTimeout, SocketError => e
        raise ClientMetadataDocumentFetchError, "Connection error: #{e.message}"
      rescue OpenSSL::SSL::SSLError => e
        raise ClientMetadataDocumentFetchError, "SSL error: #{e.message}"
      end

      def resolve_and_validate_ip(host)
        addresses = Resolv.getaddresses(host)

        if addresses.empty?
          raise ClientMetadataDocumentFetchError, "Could not resolve host: #{host}"
        end

        # Validate all resolved IPs are not private
        addresses.each do |addr|
          ip = IPAddr.new(addr)
          if private_ip?(ip)
            raise ClientMetadataDocumentFetchError, "Host resolves to private IP address"
          end
        end

        # Prefer IPv4 addresses over IPv6 for better compatibility
        ipv4_addresses = addresses.select { |addr| IPAddr.new(addr).ipv4? }
        ipv4_addresses.first || addresses.first
      rescue IPAddr::InvalidAddressError => e
        raise ClientMetadataDocumentFetchError, "Invalid IP address: #{e.message}"
      rescue Resolv::ResolvError => e
        raise ClientMetadataDocumentFetchError, "DNS resolution failed: #{e.message}"
      end

      def private_ip?(ip)
        PRIVATE_IP_RANGES.any? { |range| range.include?(ip) }
      end

      def validate_metadata!(uri, metadata)
        # client_id in metadata must match the URL
        if metadata["client_id"] != uri
          raise InvalidClientMetadataDocumentError,
            "client_id in metadata (#{metadata["client_id"]}) does not match URL (#{uri})"
        end

        # Must not contain client_secret (public clients only)
        if metadata["client_secret"].present?
          raise InvalidClientMetadataDocumentError, "Client metadata document must not contain client_secret"
        end

        # Must have at least one redirect_uri
        redirect_uris = metadata["redirect_uris"]
        if redirect_uris.blank? || !redirect_uris.is_a?(Array) || redirect_uris.empty?
          raise InvalidClientMetadataDocumentError, "Client metadata document must have redirect_uris"
        end

        # Validate redirect_uris are valid URLs
        redirect_uris.each do |redirect_uri|
          parsed = URI.parse(redirect_uri)
          unless parsed.is_a?(URI::HTTP) || parsed.is_a?(URI::HTTPS)
            raise InvalidClientMetadataDocumentError,
              "Invalid redirect_uri scheme: #{redirect_uri}"
          end
        rescue URI::InvalidURIError
          raise InvalidClientMetadataDocumentError, "Invalid redirect_uri: #{redirect_uri}"
        end

        true
      end

      def store_in_cache(uri, metadata)
        ttl = TokenAuthority.config.client_metadata_document_cache_ttl
        uri_hash = ClientMetadataDocumentCache.hash_uri(uri)

        ClientMetadataDocumentCache.find_or_initialize_by(uri_hash: uri_hash).tap do |cache|
          cache.uri = uri
          cache.metadata = metadata
          cache.expires_at = Time.current + ttl
          cache.save!
        end
      end

      def debug_event(event_name, **payload)
        return unless event_logging_enabled?
        return unless debug_events_enabled?
        return unless rails_event_available?

        full_payload = {timestamp: Time.current.iso8601(6)}.merge(payload)
        Rails.event.debug("token_authority.#{event_name}", **full_payload)
      end

      def event_logging_enabled?
        TokenAuthority.config.respond_to?(:event_logging_enabled) &&
          TokenAuthority.config.event_logging_enabled
      end

      def debug_events_enabled?
        TokenAuthority.config.respond_to?(:event_logging_debug_events) &&
          TokenAuthority.config.event_logging_debug_events
      end

      def rails_event_available?
        Rails.respond_to?(:event) && Rails.event.present?
      end
    end
  end
end
