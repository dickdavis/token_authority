# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientMetadataDocumentCache, type: :model do
  let(:uri) { "https://example.com/oauth-client" }
  let(:metadata) do
    {
      "client_id" => uri,
      "client_name" => "Example Client",
      "redirect_uris" => ["https://example.com/callback"]
    }
  end

  subject(:cache) do
    described_class.new(
      uri_hash: described_class.hash_uri(uri),
      uri: uri,
      metadata: metadata,
      expires_at: 1.hour.from_now
    )
  end

  describe "validations" do
    it { is_expected.to validate_presence_of(:uri_hash) }
    it { is_expected.to validate_uniqueness_of(:uri_hash) }
    it { is_expected.to validate_presence_of(:uri) }
    it { is_expected.to validate_presence_of(:metadata) }
    it { is_expected.to validate_presence_of(:expires_at) }
  end

  describe "scopes" do
    let!(:expired_cache) do
      described_class.create!(
        uri_hash: described_class.hash_uri("https://expired.example.com/client"),
        uri: "https://expired.example.com/client",
        metadata: metadata,
        expires_at: 1.hour.ago
      )
    end

    let!(:valid_cache) do
      described_class.create!(
        uri_hash: described_class.hash_uri("https://valid.example.com/client"),
        uri: "https://valid.example.com/client",
        metadata: metadata,
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
      expect(described_class.find_by_uri("https://unknown.example.com/client")).to be_nil
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
      hash1 = described_class.hash_uri("https://example1.com/client")
      hash2 = described_class.hash_uri("https://example2.com/client")
      expect(hash1).not_to eq(hash2)
    end
  end

  describe ".cleanup_expired!" do
    before do
      described_class.create!(
        uri_hash: described_class.hash_uri("https://expired1.example.com/client"),
        uri: "https://expired1.example.com/client",
        metadata: metadata,
        expires_at: 2.hours.ago
      )
      described_class.create!(
        uri_hash: described_class.hash_uri("https://expired2.example.com/client"),
        uri: "https://expired2.example.com/client",
        metadata: metadata,
        expires_at: 1.hour.ago
      )
      described_class.create!(
        uri_hash: described_class.hash_uri("https://valid.example.com/client"),
        uri: "https://valid.example.com/client",
        metadata: metadata,
        expires_at: 1.hour.from_now
      )
    end

    it "deletes all expired entries" do
      expect { described_class.cleanup_expired! }
        .to change(described_class, :count).from(3).to(1)
    end

    it "keeps valid entries" do
      described_class.cleanup_expired!
      expect(described_class.first.uri).to eq("https://valid.example.com/client")
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
end
