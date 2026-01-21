# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationServerMetadata, type: :model do
  subject(:model) { described_class.new(mount_path: mount_path) }

  let(:mount_path) { "/oauth" }
  let!(:original_issuer_url) { TokenAuthority.config.rfc_9068_issuer_url }

  before do
    TokenAuthority.config.rfc_9068_issuer_url = "https://example.com/"
  end

  after do
    TokenAuthority.config.rfc_9068_issuer_url = original_issuer_url
  end

  describe "#to_h" do
    it "returns the required metadata fields" do
      result = model.to_h

      aggregate_failures do
        expect(result[:issuer]).to eq("https://example.com")
        expect(result[:authorization_endpoint]).to eq("https://example.com/oauth/authorize")
        expect(result[:token_endpoint]).to eq("https://example.com/oauth/token")
        expect(result[:revocation_endpoint]).to eq("https://example.com/oauth/revoke")
        expect(result[:response_types_supported]).to eq(["code"])
        expect(result[:grant_types_supported]).to eq(["authorization_code", "refresh_token"])
        expect(result[:token_endpoint_auth_methods_supported]).to eq(TokenAuthority.config.rfc_7591_allowed_token_endpoint_auth_methods)
        expect(result[:code_challenge_methods_supported]).to eq(["S256"])
      end
    end

    it "strips trailing slash from issuer" do
      TokenAuthority.config.rfc_9068_issuer_url = "https://example.com/"
      expect(model.to_h[:issuer]).to eq("https://example.com")
    end

    it "handles issuer without trailing slash" do
      TokenAuthority.config.rfc_9068_issuer_url = "https://example.com"
      expect(model.to_h[:issuer]).to eq("https://example.com")
    end

    context "with custom mount path" do
      let(:mount_path) { "/auth" }

      it "uses the custom mount path in endpoints" do
        result = model.to_h

        aggregate_failures do
          expect(result[:authorization_endpoint]).to eq("https://example.com/auth/authorize")
          expect(result[:token_endpoint]).to eq("https://example.com/auth/token")
          expect(result[:revocation_endpoint]).to eq("https://example.com/auth/revoke")
        end
      end
    end

    context "when scopes_supported is configured" do
      before do
        TokenAuthority.config.rfc_8414_scopes_supported = ["read", "write"]
      end

      after do
        TokenAuthority.config.rfc_8414_scopes_supported = []
      end

      it "includes scopes_supported in the response" do
        expect(model.to_h[:scopes_supported]).to eq(["read", "write"])
      end
    end

    context "when scopes_supported is empty" do
      before do
        TokenAuthority.config.rfc_8414_scopes_supported = []
      end

      it "omits scopes_supported from the response" do
        expect(model.to_h).not_to have_key(:scopes_supported)
      end
    end

    context "when service_documentation is configured" do
      before do
        TokenAuthority.config.rfc_8414_service_documentation = "https://example.com/docs/oauth"
      end

      after do
        TokenAuthority.config.rfc_8414_service_documentation = nil
      end

      it "includes service_documentation in the response" do
        expect(model.to_h[:service_documentation]).to eq("https://example.com/docs/oauth")
      end
    end

    context "when service_documentation is nil" do
      before do
        TokenAuthority.config.rfc_8414_service_documentation = nil
      end

      it "omits service_documentation from the response" do
        expect(model.to_h).not_to have_key(:service_documentation)
      end
    end
  end
end
