# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::JwksCache, type: :model do
  let(:uri) { "https://example.com/.well-known/jwks.json" }
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

  subject(:cache) do
    described_class.new(
      uri_hash: described_class.hash_uri(uri),
      uri: uri,
      jwks: jwks_data,
      expires_at: 1.hour.from_now
    )
  end

  describe "validations" do
    it { is_expected.to validate_presence_of(:uri_hash) }
    it { is_expected.to validate_uniqueness_of(:uri_hash) }
    it { is_expected.to validate_presence_of(:uri) }
    it { is_expected.to validate_presence_of(:jwks) }
    it { is_expected.to validate_presence_of(:expires_at) }
  end

  describe "scopes" do
    let!(:expired_cache) do
      described_class.create!(
        uri_hash: described_class.hash_uri("https://expired.example.com/jwks.json"),
        uri: "https://expired.example.com/jwks.json",
        jwks: jwks_data,
        expires_at: 1.hour.ago
      )
    end

    let!(:valid_cache) do
      described_class.create!(
        uri_hash: described_class.hash_uri("https://valid.example.com/jwks.json"),
        uri: "https://valid.example.com/jwks.json",
        jwks: jwks_data,
        expires_at: 1.hour.from_now
      )
    end

    describe ".expired" do
      it "returns only expired entries" do
        expect(described_class.expired).to contain_exactly(expired_cache)
      end
    end

    describe ".valid" do
      it "returns only non-expired entries" do
        expect(described_class.valid).to contain_exactly(valid_cache)
      end
    end
  end

  describe ".find_by_uri" do
    before { cache.save! }

    it "finds a cache entry by URI" do
      expect(described_class.find_by_uri(uri)).to eq(cache)
    end

    it "returns nil for unknown URI" do
      expect(described_class.find_by_uri("https://unknown.example.com/jwks.json")).to be_nil
    end
  end

  describe ".hash_uri" do
    it "returns a SHA256 hex digest of the URI" do
      expected_hash = Digest::SHA256.hexdigest(uri)
      expect(described_class.hash_uri(uri)).to eq(expected_hash)
    end

    it "returns the same hash for the same URI" do
      hash1 = described_class.hash_uri(uri)
      hash2 = described_class.hash_uri(uri)
      expect(hash1).to eq(hash2)
    end

    it "returns different hashes for different URIs" do
      hash1 = described_class.hash_uri("https://example1.com/jwks.json")
      hash2 = described_class.hash_uri("https://example2.com/jwks.json")
      expect(hash1).not_to eq(hash2)
    end
  end

  describe ".cleanup_expired!" do
    before do
      described_class.create!(
        uri_hash: described_class.hash_uri("https://expired1.example.com/jwks.json"),
        uri: "https://expired1.example.com/jwks.json",
        jwks: jwks_data,
        expires_at: 2.hours.ago
      )
      described_class.create!(
        uri_hash: described_class.hash_uri("https://expired2.example.com/jwks.json"),
        uri: "https://expired2.example.com/jwks.json",
        jwks: jwks_data,
        expires_at: 1.hour.ago
      )
      described_class.create!(
        uri_hash: described_class.hash_uri("https://valid.example.com/jwks.json"),
        uri: "https://valid.example.com/jwks.json",
        jwks: jwks_data,
        expires_at: 1.hour.from_now
      )
    end

    it "deletes all expired entries" do
      expect { described_class.cleanup_expired! }
        .to change(described_class, :count).from(3).to(1)
    end

    it "keeps valid entries" do
      described_class.cleanup_expired!
      expect(described_class.first.uri).to eq("https://valid.example.com/jwks.json")
    end
  end

  describe "#expired?" do
    context "when expires_at is in the past" do
      before { cache.expires_at = 1.hour.ago }

      it "returns true" do
        expect(cache.expired?).to be true
      end
    end

    context "when expires_at is now" do
      before { cache.expires_at = Time.current }

      it "returns true" do
        expect(cache.expired?).to be true
      end
    end

    context "when expires_at is in the future" do
      before { cache.expires_at = 1.hour.from_now }

      it "returns false" do
        expect(cache.expired?).to be false
      end
    end
  end

  describe "#to_jwk_set" do
    before { cache.save! }

    it "returns a JWT::JWK::Set" do
      expect(cache.to_jwk_set).to be_a(JWT::JWK::Set)
    end

    it "contains the stored keys" do
      jwk_set = cache.to_jwk_set
      expect(jwk_set.keys.first[:kid]).to eq("test-key-1")
    end
  end
end
