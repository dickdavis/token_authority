# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::JwksFetcher, type: :model do
  let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }
  let(:jwks_data) do
    {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "test-key-1",
          "use" => "sig",
          "alg" => "RS256",
          "n" => "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e" => "AQAB"
        }
      ]
    }
  end

  describe ".fetch" do
    context "when JWKS is not cached" do
      before do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_data.to_json, headers: {"Content-Type" => "application/json"})
      end

      it "fetches JWKS from the URI" do
        result = described_class.fetch(jwks_uri)

        expect(result).to be_a(JWT::JWK::Set)
        expect(a_request(:get, jwks_uri)).to have_been_made.once
      end

      it "caches the fetched JWKS" do
        expect { described_class.fetch(jwks_uri) }
          .to change(TokenAuthority::JwksCache, :count).by(1)
      end

      it "stores the correct data in the cache" do
        described_class.fetch(jwks_uri)

        cache = TokenAuthority::JwksCache.find_by_uri(jwks_uri)
        expect(cache.uri).to eq(jwks_uri)
        expect(cache.jwks).to eq(jwks_data)
        expect(cache.expires_at).to be > Time.current
      end
    end

    context "when JWKS is cached and not expired" do
      before do
        TokenAuthority::JwksCache.create!(
          uri_hash: TokenAuthority::JwksCache.hash_uri(jwks_uri),
          uri: jwks_uri,
          jwks: jwks_data,
          expires_at: 1.hour.from_now
        )
      end

      it "returns the cached JWKS without making a request" do
        result = described_class.fetch(jwks_uri)

        expect(result).to be_a(JWT::JWK::Set)
        expect(a_request(:get, jwks_uri)).not_to have_been_made
      end
    end

    context "when JWKS is cached but expired" do
      before do
        TokenAuthority::JwksCache.create!(
          uri_hash: TokenAuthority::JwksCache.hash_uri(jwks_uri),
          uri: jwks_uri,
          jwks: jwks_data,
          expires_at: 1.hour.ago
        )

        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_data.to_json, headers: {"Content-Type" => "application/json"})
      end

      it "fetches fresh JWKS from the URI" do
        described_class.fetch(jwks_uri)

        expect(a_request(:get, jwks_uri)).to have_been_made.once
      end

      it "updates the cache with new expiration" do
        described_class.fetch(jwks_uri)

        cache = TokenAuthority::JwksCache.find_by_uri(jwks_uri)
        expect(cache.expires_at).to be > Time.current
      end
    end

    context "when URI is not HTTPS" do
      let(:http_uri) { "http://example.com/.well-known/jwks.json" }

      it "raises a FetchError" do
        expect { described_class.fetch(http_uri) }
          .to raise_error(TokenAuthority::JwksFetcher::FetchError, /Invalid URI scheme/)
      end
    end

    context "when URI is invalid" do
      let(:invalid_uri) { "not a valid uri" }

      it "raises a FetchError" do
        expect { described_class.fetch(invalid_uri) }
          .to raise_error(TokenAuthority::JwksFetcher::FetchError, /Invalid JWKS URI/)
      end
    end

    context "when HTTP request fails" do
      before do
        stub_request(:get, jwks_uri).to_return(status: 500, body: "Internal Server Error")
      end

      it "raises a FetchError" do
        expect { described_class.fetch(jwks_uri) }
          .to raise_error(TokenAuthority::JwksFetcher::FetchError, /HTTP 500/)
      end
    end

    context "when response is not valid JSON" do
      before do
        stub_request(:get, jwks_uri).to_return(status: 200, body: "not json")
      end

      it "raises a FetchError" do
        expect { described_class.fetch(jwks_uri) }
          .to raise_error(TokenAuthority::JwksFetcher::FetchError, /Invalid JWKS JSON/)
      end
    end
  end

  describe ".clear_cache" do
    it "removes the cached entry for the given URI" do
      TokenAuthority::JwksCache.create!(
        uri_hash: TokenAuthority::JwksCache.hash_uri(jwks_uri),
        uri: jwks_uri,
        jwks: jwks_data,
        expires_at: 1.hour.from_now
      )

      expect { described_class.clear_cache(jwks_uri) }
        .to change(TokenAuthority::JwksCache, :count).by(-1)
    end

    it "does nothing if the URI is not cached" do
      expect { described_class.clear_cache(jwks_uri) }.not_to raise_error
    end
  end

  describe ".cleanup_expired!" do
    it "delegates to JwksCache.cleanup_expired!" do
      allow(TokenAuthority::JwksCache).to receive(:cleanup_expired!)

      described_class.cleanup_expired!

      expect(TokenAuthority::JwksCache).to have_received(:cleanup_expired!)
    end
  end
end
