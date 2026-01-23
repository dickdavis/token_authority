# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ResourceUriValidator do
  describe ".valid?" do
    context "with valid resource URIs" do
      it "returns true for http URIs" do
        expect(described_class.valid?("http://example.com")).to be true
      end

      it "returns true for https URIs" do
        expect(described_class.valid?("https://example.com")).to be true
      end

      it "returns true for URIs with paths" do
        expect(described_class.valid?("https://example.com/api/v1")).to be true
      end

      it "returns true for URIs with query strings" do
        expect(described_class.valid?("https://example.com/api?version=1")).to be true
      end

      it "returns true for URIs with ports" do
        expect(described_class.valid?("https://example.com:8443/api")).to be true
      end
    end

    context "with invalid resource URIs" do
      it "returns false for nil" do
        expect(described_class.valid?(nil)).to be false
      end

      it "returns false for empty string" do
        expect(described_class.valid?("")).to be false
      end

      it "returns false for URIs with fragments" do
        expect(described_class.valid?("https://example.com#fragment")).to be false
      end

      it "returns false for non-http/https schemes" do
        expect(described_class.valid?("ftp://example.com")).to be false
      end

      it "returns false for relative URIs" do
        expect(described_class.valid?("/api/v1")).to be false
      end

      it "returns false for URIs without host" do
        expect(described_class.valid?("http://")).to be false
      end

      it "returns false for invalid URIs" do
        expect(described_class.valid?("not a uri")).to be false
      end
    end
  end

  describe ".valid_all?" do
    it "returns true for empty array" do
      expect(described_class.valid_all?([])).to be true
    end

    it "returns true for nil" do
      expect(described_class.valid_all?(nil)).to be true
    end

    it "returns true when all URIs are valid" do
      resources = ["https://api1.example.com", "https://api2.example.com"]
      expect(described_class.valid_all?(resources)).to be true
    end

    it "returns false when any URI is invalid" do
      resources = ["https://api.example.com", "not-valid"]
      expect(described_class.valid_all?(resources)).to be false
    end
  end

  describe ".allowed?" do
    context "when RFC 8707 is not enabled (no resources configured)" do
      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(nil)
      end

      it "returns false for any URI" do
        expect(described_class.allowed?("https://example.com")).to be false
      end
    end

    context "when RFC 8707 is enabled with configured resources" do
      let(:configured_resources) do
        {
          "https://api.example.com" => "Main API",
          "https://other.example.com" => "Other API"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(configured_resources)
      end

      it "returns true for allowed URIs" do
        expect(described_class.allowed?("https://api.example.com")).to be true
      end

      it "returns false for non-allowed URIs" do
        expect(described_class.allowed?("https://unknown.example.com")).to be false
      end
    end
  end

  describe ".allowed_all?" do
    context "when RFC 8707 is not enabled (no resources configured)" do
      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(nil)
      end

      it "returns true for empty array" do
        expect(described_class.allowed_all?([])).to be true
      end

      it "returns false for any non-empty resources" do
        resources = ["https://api.example.com", "https://other.example.com"]
        expect(described_class.allowed_all?(resources)).to be false
      end
    end

    context "when RFC 8707 is enabled with configured resources" do
      let(:configured_resources) do
        {
          "https://api.example.com" => "Main API",
          "https://other.example.com" => "Other API"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(configured_resources)
      end

      it "returns true for empty array" do
        expect(described_class.allowed_all?([])).to be true
      end

      it "returns true when all resources are allowed" do
        resources = ["https://api.example.com"]
        expect(described_class.allowed_all?(resources)).to be true
      end

      it "returns false when any resource is not allowed" do
        resources = ["https://api.example.com", "https://unknown.example.com"]
        expect(described_class.allowed_all?(resources)).to be false
      end
    end
  end

  describe ".subset?" do
    it "returns true when granted is empty" do
      expect(described_class.subset?(["https://api.example.com"], [])).to be true
    end

    it "returns true when granted is nil" do
      expect(described_class.subset?(["https://api.example.com"], nil)).to be true
    end

    it "returns true when requested is empty" do
      expect(described_class.subset?([], ["https://api.example.com"])).to be true
    end

    it "returns true when requested is a subset of granted" do
      granted = ["https://api1.example.com", "https://api2.example.com"]
      requested = ["https://api1.example.com"]
      expect(described_class.subset?(requested, granted)).to be true
    end

    it "returns true when requested equals granted" do
      resources = ["https://api.example.com"]
      expect(described_class.subset?(resources, resources)).to be true
    end

    it "returns false when requested contains resources not in granted" do
      granted = ["https://api1.example.com"]
      requested = ["https://api1.example.com", "https://api2.example.com"]
      expect(described_class.subset?(requested, granted)).to be false
    end
  end
end
