# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientMetadataDocumentFetcher, type: :model do
  let(:client_id_url) { "https://example.com/oauth-client" }
  let(:metadata) do
    {
      "client_id" => client_id_url,
      "client_name" => "Example Client",
      "redirect_uris" => ["https://example.com/callback"]
    }
  end

  describe ".fetch" do
    context "when metadata is not cached" do
      before do
        stub_request(:get, client_id_url)
          .to_return(status: 200, body: metadata.to_json, headers: {"Content-Type" => "application/json"})

        # Stub DNS resolution to return a public IP
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
      end

      it "fetches metadata from the URI" do
        result = described_class.fetch(client_id_url)

        expect(result).to eq(metadata)
        expect(a_request(:get, client_id_url)).to have_been_made.once
      end

      it "caches the fetched metadata" do
        expect { described_class.fetch(client_id_url) }
          .to change(TokenAuthority::ClientMetadataDocumentCache, :count).by(1)
      end

      it "stores the correct data in the cache" do
        described_class.fetch(client_id_url)

        cache = TokenAuthority::ClientMetadataDocumentCache.find_by_uri(client_id_url)
        expect(cache.uri).to eq(client_id_url)
        expect(cache.metadata).to eq(metadata)
        expect(cache.expires_at).to be > Time.current
      end
    end

    context "when metadata is cached and not expired" do
      before do
        TokenAuthority::ClientMetadataDocumentCache.create!(
          uri_hash: TokenAuthority::ClientMetadataDocumentCache.hash_uri(client_id_url),
          uri: client_id_url,
          metadata: metadata,
          expires_at: 1.hour.from_now
        )
      end

      it "returns the cached metadata without making a request" do
        result = described_class.fetch(client_id_url)

        expect(result["client_id"]).to eq(client_id_url)
        expect(a_request(:get, client_id_url)).not_to have_been_made
      end
    end

    context "when metadata is cached but expired" do
      before do
        TokenAuthority::ClientMetadataDocumentCache.create!(
          uri_hash: TokenAuthority::ClientMetadataDocumentCache.hash_uri(client_id_url),
          uri: client_id_url,
          metadata: metadata,
          expires_at: 1.hour.ago
        )

        stub_request(:get, client_id_url)
          .to_return(status: 200, body: metadata.to_json, headers: {"Content-Type" => "application/json"})

        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
      end

      it "fetches fresh metadata from the URI" do
        described_class.fetch(client_id_url)

        expect(a_request(:get, client_id_url)).to have_been_made.once
      end

      it "updates the cache with new expiration" do
        described_class.fetch(client_id_url)

        cache = TokenAuthority::ClientMetadataDocumentCache.find_by_uri(client_id_url)
        expect(cache.expires_at).to be > Time.current
      end
    end

    context "when URI is not HTTPS" do
      let(:http_url) { "http://example.com/oauth-client" }

      it "raises an InvalidClientMetadataDocumentUrlError" do
        expect { described_class.fetch(http_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentUrlError, /HTTPS/)
      end
    end

    context "when URI has no path" do
      let(:no_path_url) { "https://example.com" }

      it "raises an InvalidClientMetadataDocumentUrlError" do
        expect { described_class.fetch(no_path_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentUrlError, /path/)
      end
    end

    context "when URI has only root path" do
      let(:root_path_url) { "https://example.com/" }

      it "raises an InvalidClientMetadataDocumentUrlError" do
        expect { described_class.fetch(root_path_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentUrlError, /path/)
      end
    end

    context "when URI has a fragment" do
      let(:fragment_url) { "https://example.com/oauth-client#section" }

      it "raises an InvalidClientMetadataDocumentUrlError" do
        expect { described_class.fetch(fragment_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentUrlError, /fragment/)
      end
    end

    context "when URI has credentials" do
      let(:credentials_url) { "https://user:pass@example.com/oauth-client" }

      it "raises an InvalidClientMetadataDocumentUrlError" do
        expect { described_class.fetch(credentials_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentUrlError, /credentials/)
      end
    end

    context "when host is blocked" do
      before do
        TokenAuthority.config.client_metadata_document_blocked_hosts = ["blocked.example.com"]
      end

      after do
        TokenAuthority.config.client_metadata_document_blocked_hosts = []
      end

      let(:blocked_url) { "https://blocked.example.com/oauth-client" }

      it "raises an InvalidClientMetadataDocumentUrlError" do
        expect { described_class.fetch(blocked_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentUrlError, /blocked/)
      end
    end

    context "when host resolves to private IP" do
      before do
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["127.0.0.1"])
      end

      it "raises a ClientMetadataDocumentFetchError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::ClientMetadataDocumentFetchError, /private IP/)
      end
    end

    context "when HTTP request fails" do
      before do
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
        stub_request(:get, client_id_url).to_return(status: 500, body: "Internal Server Error")
      end

      it "raises a ClientMetadataDocumentFetchError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::ClientMetadataDocumentFetchError, /HTTP 500/)
      end
    end

    context "when response is not valid JSON" do
      before do
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
        stub_request(:get, client_id_url).to_return(status: 200, body: "not json")
      end

      it "raises a ClientMetadataDocumentFetchError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::ClientMetadataDocumentFetchError, /Invalid JSON/)
      end
    end

    context "when client_id in metadata does not match URL" do
      let(:mismatched_metadata) do
        {
          "client_id" => "https://other.example.com/oauth-client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end

      before do
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
        stub_request(:get, client_id_url)
          .to_return(status: 200, body: mismatched_metadata.to_json)
      end

      it "raises an InvalidClientMetadataDocumentError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentError, /does not match/)
      end
    end

    context "when metadata contains client_secret" do
      let(:secret_metadata) do
        {
          "client_id" => client_id_url,
          "client_secret" => "some-secret",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end

      before do
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
        stub_request(:get, client_id_url)
          .to_return(status: 200, body: secret_metadata.to_json)
      end

      it "raises an InvalidClientMetadataDocumentError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentError, /client_secret/)
      end
    end

    context "when metadata is missing redirect_uris" do
      let(:no_redirects_metadata) do
        {
          "client_id" => client_id_url
        }
      end

      before do
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
        stub_request(:get, client_id_url)
          .to_return(status: 200, body: no_redirects_metadata.to_json)
      end

      it "raises an InvalidClientMetadataDocumentError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::InvalidClientMetadataDocumentError, /redirect_uris/)
      end
    end

    context "when response exceeds max size" do
      before do
        TokenAuthority.config.client_metadata_document_max_response_size = 100
        allow(Resolv).to receive(:getaddresses).with("example.com").and_return(["93.184.216.34"])
        stub_request(:get, client_id_url)
          .to_return(status: 200, body: "x" * 200)
      end

      after do
        TokenAuthority.config.client_metadata_document_max_response_size = 5120
      end

      it "raises a ClientMetadataDocumentFetchError" do
        expect { described_class.fetch(client_id_url) }
          .to raise_error(TokenAuthority::ClientMetadataDocumentFetchError, /exceeds maximum size/)
      end
    end
  end

  describe ".valid_client_id_url?" do
    it "returns true for valid HTTPS URLs with path" do
      expect(described_class.valid_client_id_url?("https://example.com/oauth-client")).to be true
    end

    it "returns false for HTTP URLs" do
      expect(described_class.valid_client_id_url?("http://example.com/oauth-client")).to be false
    end

    it "returns false for URLs without path" do
      expect(described_class.valid_client_id_url?("https://example.com")).to be false
    end

    it "returns false for URLs with fragments" do
      expect(described_class.valid_client_id_url?("https://example.com/client#section")).to be false
    end
  end

  describe ".clear_cache" do
    before do
      TokenAuthority::ClientMetadataDocumentCache.create!(
        uri_hash: TokenAuthority::ClientMetadataDocumentCache.hash_uri(client_id_url),
        uri: client_id_url,
        metadata: metadata,
        expires_at: 1.hour.from_now
      )
    end

    it "removes the cached entry for the given URI" do
      expect { described_class.clear_cache(client_id_url) }
        .to change(TokenAuthority::ClientMetadataDocumentCache, :count).by(-1)
    end

    it "does nothing if the URI is not cached" do
      expect { described_class.clear_cache("https://unknown.example.com/client") }.not_to raise_error
    end
  end

  describe ".cleanup_expired!" do
    it "delegates to ClientMetadataDocumentCache.cleanup_expired!" do
      allow(TokenAuthority::ClientMetadataDocumentCache).to receive(:cleanup_expired!)

      described_class.cleanup_expired!

      expect(TokenAuthority::ClientMetadataDocumentCache).to have_received(:cleanup_expired!)
    end
  end
end
