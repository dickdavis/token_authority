# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientIdResolver, type: :model do
  describe ".resolve" do
    context "with nil client_id" do
      it "returns nil" do
        expect(described_class.resolve(nil)).to be_nil
      end
    end

    context "with blank client_id" do
      it "returns nil" do
        expect(described_class.resolve("")).to be_nil
      end
    end

    context "with a UUID-based client_id" do
      let!(:client) { create(:token_authority_client) }

      it "returns the registered Client" do
        result = described_class.resolve(client.public_id)
        expect(result).to eq(client)
      end

      it "instruments client resolution for registered clients" do
        expect { described_class.resolve(client.public_id) }
          .to instrument("token_authority.client.resolve")
          .with_payload(client_type: "registered")
      end

      context "when client does not exist" do
        it "raises ClientNotFoundError" do
          expect { described_class.resolve("non-existent-uuid") }
            .to raise_error(TokenAuthority::ClientNotFoundError)
        end
      end
    end

    context "with a URL-based client_id" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end

      before do
        allow(TokenAuthority::ClientMetadataDocumentFetcher)
          .to receive(:fetch)
          .with(client_id_url)
          .and_return(metadata)
      end

      it "returns a ClientMetadataDocument" do
        result = described_class.resolve(client_id_url)

        expect(result).to be_a(TokenAuthority::ClientMetadataDocument)
        expect(result.public_id).to eq(client_id_url)
      end

      it "instruments client resolution for URL-based clients" do
        expect { described_class.resolve(client_id_url) }
          .to instrument("token_authority.client.resolve")
          .with_payload(client_type: "url_based")
      end

      context "when fetching fails with InvalidClientMetadataDocumentUrlError" do
        before do
          allow(TokenAuthority::ClientMetadataDocumentFetcher)
            .to receive(:fetch)
            .with(client_id_url)
            .and_raise(TokenAuthority::InvalidClientMetadataDocumentUrlError)
        end

        it "raises ClientNotFoundError" do
          expect { described_class.resolve(client_id_url) }
            .to raise_error(TokenAuthority::ClientNotFoundError)
        end
      end

      context "when fetching fails with ClientMetadataDocumentFetchError" do
        before do
          allow(TokenAuthority::ClientMetadataDocumentFetcher)
            .to receive(:fetch)
            .with(client_id_url)
            .and_raise(TokenAuthority::ClientMetadataDocumentFetchError)
        end

        it "raises ClientNotFoundError" do
          expect { described_class.resolve(client_id_url) }
            .to raise_error(TokenAuthority::ClientNotFoundError)
        end
      end

      context "when metadata is invalid" do
        before do
          allow(TokenAuthority::ClientMetadataDocumentFetcher)
            .to receive(:fetch)
            .with(client_id_url)
            .and_raise(TokenAuthority::InvalidClientMetadataDocumentError)
        end

        it "raises ClientNotFoundError" do
          expect { described_class.resolve(client_id_url) }
            .to raise_error(TokenAuthority::ClientNotFoundError)
        end
      end

      context "when client_metadata_document_enabled is false" do
        before do
          TokenAuthority.config.client_metadata_document_enabled = false
        end

        after do
          TokenAuthority.config.client_metadata_document_enabled = true
        end

        it "treats URL as UUID and raises ClientNotFoundError" do
          expect { described_class.resolve(client_id_url) }
            .to raise_error(TokenAuthority::ClientNotFoundError)
        end
      end
    end
  end

  describe ".url_based_client_id?" do
    it "returns false for nil" do
      expect(described_class.url_based_client_id?(nil)).to be false
    end

    it "returns false for blank string" do
      expect(described_class.url_based_client_id?("")).to be false
    end

    it "returns false for UUID-like strings" do
      expect(described_class.url_based_client_id?("550e8400-e29b-41d4-a716-446655440000")).to be false
    end

    it "returns true for HTTPS URLs" do
      expect(described_class.url_based_client_id?("https://example.com/oauth-client")).to be true
    end

    it "returns false for HTTP URLs" do
      expect(described_class.url_based_client_id?("http://example.com/oauth-client")).to be false
    end

    context "when client_metadata_document_enabled is false" do
      before do
        TokenAuthority.config.client_metadata_document_enabled = false
      end

      after do
        TokenAuthority.config.client_metadata_document_enabled = true
      end

      it "returns false for HTTPS URLs" do
        expect(described_class.url_based_client_id?("https://example.com/oauth-client")).to be false
      end
    end
  end
end
