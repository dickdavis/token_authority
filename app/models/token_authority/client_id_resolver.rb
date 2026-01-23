# frozen_string_literal: true

module TokenAuthority
  # Resolves a client_id to the appropriate client representation.
  #
  # This service object handles both traditional registered clients (identified by UUID)
  # and URL-based clients that use client metadata documents per
  # draft-ietf-oauth-client-id-metadata-document.
  #
  # The resolver determines which type of client is being used based on the format
  # of the client_id:
  # - HTTPS URLs are resolved as URL-based clients (fetching metadata documents)
  # - UUIDs are resolved as registered clients (database lookups)
  #
  # URL-based client support can be disabled via configuration, in which case only
  # registered clients are supported.
  #
  # @example Resolving a registered client
  #   client = ClientIdResolver.resolve("550e8400-e29b-41d4-a716-446655440000")
  #   client.class # => TokenAuthority::Client
  #
  # @example Resolving a URL-based client
  #   client = ClientIdResolver.resolve("https://client.example.com/.well-known/oauth-client")
  #   client.class # => TokenAuthority::ClientMetadataDocument
  #
  # @since 0.2.0
  class ClientIdResolver
    extend TokenAuthority::Instrumentation

    class << self
      # Resolves a client_id to either a Client or ClientMetadataDocument.
      #
      # Emits instrumentation events with the client type for monitoring.
      #
      # @param client_id [String] the client identifier (UUID or HTTPS URL)
      #
      # @return [TokenAuthority::Client, TokenAuthority::ClientMetadataDocument, nil]
      #   the resolved client, or nil if client_id is blank
      #
      # @raise [TokenAuthority::ClientNotFoundError] if the client cannot be found
      #   or the metadata document cannot be fetched
      #
      # @example
      #   client = ClientIdResolver.resolve(params[:client_id])
      #   if client.public_client_type?
      #     # Handle public client
      #   end
      def resolve(client_id)
        instrument("client.resolve") do |payload|
          return nil if client_id.blank?

          # Check if it's a URL-based client_id
          if url_based_client_id?(client_id)
            payload[:client_type] = "url_based"
            resolve_url_based(client_id)
          else
            payload[:client_type] = "registered"
            resolve_uuid_based(client_id)
          end
        end
      end

      # Checks if a client_id represents a URL-based client.
      #
      # URL-based clients are identified by HTTPS URLs and are only supported
      # when client_metadata_document_enabled is true in the configuration.
      #
      # @param client_id [String] the client identifier to check
      #
      # @return [Boolean] true if this is a URL-based client_id
      def url_based_client_id?(client_id)
        return false if client_id.blank?
        return false unless TokenAuthority.config.client_metadata_document_enabled

        # Check if it looks like a URL
        client_id.start_with?("https://")
      end

      private

      # Resolves a URL-based client by fetching its metadata document.
      #
      # @param client_id [String] the HTTPS URL of the client
      #
      # @return [TokenAuthority::ClientMetadataDocument] the metadata document
      #
      # @raise [TokenAuthority::ClientNotFoundError] if fetching or parsing fails
      # @api private
      def resolve_url_based(client_id)
        # Validate and fetch the metadata document
        metadata = ClientMetadataDocumentFetcher.fetch(client_id)
        ClientMetadataDocument.new(metadata)
      rescue InvalidClientMetadataDocumentUrlError, ClientMetadataDocumentFetchError, InvalidClientMetadataDocumentError
        # If URL-based resolution fails, raise ClientNotFoundError for consistent error handling
        raise ClientNotFoundError
      end

      # Resolves a UUID-based registered client from the database.
      #
      # @param client_id [String] the UUID of the client
      #
      # @return [TokenAuthority::Client] the registered client
      #
      # @raise [TokenAuthority::ClientNotFoundError] if no client is found
      # @api private
      def resolve_uuid_based(client_id)
        client = TokenAuthority::Client.find_by(public_id: client_id)
        raise ClientNotFoundError if client.nil?

        client
      end
    end
  end
end
