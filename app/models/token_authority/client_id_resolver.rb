# frozen_string_literal: true

module TokenAuthority
  ##
  # Resolves a client_id to either a registered Client (UUID-based) or a
  # ClientMetadataDocument (URL-based).
  class ClientIdResolver
    extend TokenAuthority::Instrumentation

    class << self
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

      def url_based_client_id?(client_id)
        return false if client_id.blank?
        return false unless TokenAuthority.config.client_metadata_document_enabled

        # Check if it looks like a URL
        client_id.start_with?("https://")
      end

      private

      def resolve_url_based(client_id)
        # Validate and fetch the metadata document
        metadata = ClientMetadataDocumentFetcher.fetch(client_id)
        ClientMetadataDocument.new(metadata)
      rescue InvalidClientMetadataDocumentUrlError, ClientMetadataDocumentFetchError, InvalidClientMetadataDocumentError
        # If URL-based resolution fails, raise ClientNotFoundError for consistent error handling
        raise ClientNotFoundError
      end

      def resolve_uuid_based(client_id)
        client = TokenAuthority::Client.find_by(public_id: client_id)
        raise ClientNotFoundError if client.nil?

        client
      end
    end
  end
end
