# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ProtectedResourceMetadata, type: :model do
  subject(:model) { described_class.new(mount_path: mount_path) }

  let(:mount_path) { "/oauth" }
  let!(:original_config) do
    {
      rfc_9068_issuer_url: TokenAuthority.config.rfc_9068_issuer_url,
      rfc_8414_scopes_supported: TokenAuthority.config.rfc_8414_scopes_supported,
      rfc_9728_resource: TokenAuthority.config.rfc_9728_resource,
      rfc_9728_scopes_supported: TokenAuthority.config.rfc_9728_scopes_supported,
      rfc_9728_authorization_servers: TokenAuthority.config.rfc_9728_authorization_servers,
      rfc_9728_bearer_methods_supported: TokenAuthority.config.rfc_9728_bearer_methods_supported,
      rfc_9728_jwks_uri: TokenAuthority.config.rfc_9728_jwks_uri,
      rfc_9728_resource_name: TokenAuthority.config.rfc_9728_resource_name,
      rfc_9728_resource_documentation: TokenAuthority.config.rfc_9728_resource_documentation,
      rfc_9728_resource_policy_uri: TokenAuthority.config.rfc_9728_resource_policy_uri,
      rfc_9728_resource_tos_uri: TokenAuthority.config.rfc_9728_resource_tos_uri
    }
  end

  before do
    TokenAuthority.config.rfc_9068_issuer_url = "https://example.com/"
  end

  after do
    original_config.each do |key, value|
      TokenAuthority.config.send("#{key}=", value)
    end
  end

  describe "#to_h" do
    it "returns the required resource field" do
      expect(model.to_h[:resource]).to eq("https://example.com")
    end

    it "returns the authorization_servers field" do
      expect(model.to_h[:authorization_servers]).to eq(["https://example.com"])
    end

    it "strips trailing slash from resource" do
      TokenAuthority.config.rfc_9068_issuer_url = "https://example.com/"
      expect(model.to_h[:resource]).to eq("https://example.com")
    end

    it "handles issuer without trailing slash" do
      TokenAuthority.config.rfc_9068_issuer_url = "https://example.com"
      expect(model.to_h[:resource]).to eq("https://example.com")
    end

    context "with custom rfc_9728_resource configured" do
      before do
        TokenAuthority.config.rfc_9728_resource = "https://api.example.com/"
      end

      it "uses the configured rfc_9728_resource" do
        expect(model.to_h[:resource]).to eq("https://api.example.com/")
      end
    end

    context "with custom rfc_9728_authorization_servers configured" do
      before do
        TokenAuthority.config.rfc_9728_authorization_servers = [
          "https://auth1.example.com",
          "https://auth2.example.com"
        ]
      end

      it "uses the configured authorization_servers" do
        expect(model.to_h[:authorization_servers]).to eq([
          "https://auth1.example.com",
          "https://auth2.example.com"
        ])
      end
    end

    context "when rfc_9728_scopes_supported is configured" do
      before do
        TokenAuthority.config.rfc_9728_scopes_supported = ["api:read", "api:write"]
      end

      it "includes scopes_supported in the response" do
        expect(model.to_h[:scopes_supported]).to eq(["api:read", "api:write"])
      end
    end

    context "when rfc_9728_scopes_supported is not configured but rfc_8414_scopes_supported is" do
      before do
        TokenAuthority.config.rfc_9728_scopes_supported = nil
        TokenAuthority.config.rfc_8414_scopes_supported = ["read", "write"]
      end

      it "falls back to rfc_8414_scopes_supported" do
        expect(model.to_h[:scopes_supported]).to eq(["read", "write"])
      end
    end

    context "when no scopes are configured" do
      before do
        TokenAuthority.config.rfc_9728_scopes_supported = nil
        TokenAuthority.config.rfc_8414_scopes_supported = []
      end

      it "omits scopes_supported from the response" do
        expect(model.to_h).not_to have_key(:scopes_supported)
      end
    end

    context "when bearer_methods_supported is configured" do
      before do
        TokenAuthority.config.rfc_9728_bearer_methods_supported = ["header", "body"]
      end

      it "includes bearer_methods_supported in the response" do
        expect(model.to_h[:bearer_methods_supported]).to eq(["header", "body"])
      end
    end

    context "when bearer_methods_supported is not configured" do
      before do
        TokenAuthority.config.rfc_9728_bearer_methods_supported = nil
      end

      it "omits bearer_methods_supported from the response" do
        expect(model.to_h).not_to have_key(:bearer_methods_supported)
      end
    end

    context "when jwks_uri is configured" do
      before do
        TokenAuthority.config.rfc_9728_jwks_uri = "https://example.com/.well-known/jwks.json"
      end

      it "includes jwks_uri in the response" do
        expect(model.to_h[:jwks_uri]).to eq("https://example.com/.well-known/jwks.json")
      end
    end

    context "when jwks_uri is not configured" do
      before do
        TokenAuthority.config.rfc_9728_jwks_uri = nil
      end

      it "omits jwks_uri from the response" do
        expect(model.to_h).not_to have_key(:jwks_uri)
      end
    end

    context "when resource_name is configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_name = "Example API"
      end

      it "includes resource_name in the response" do
        expect(model.to_h[:resource_name]).to eq("Example API")
      end
    end

    context "when resource_name is not configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_name = nil
      end

      it "omits resource_name from the response" do
        expect(model.to_h).not_to have_key(:resource_name)
      end
    end

    context "when resource_documentation is configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_documentation = "https://example.com/docs/api"
      end

      it "includes resource_documentation in the response" do
        expect(model.to_h[:resource_documentation]).to eq("https://example.com/docs/api")
      end
    end

    context "when resource_documentation is not configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_documentation = nil
      end

      it "omits resource_documentation from the response" do
        expect(model.to_h).not_to have_key(:resource_documentation)
      end
    end

    context "when resource_policy_uri is configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_policy_uri = "https://example.com/privacy"
      end

      it "includes resource_policy_uri in the response" do
        expect(model.to_h[:resource_policy_uri]).to eq("https://example.com/privacy")
      end
    end

    context "when resource_policy_uri is not configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_policy_uri = nil
      end

      it "omits resource_policy_uri from the response" do
        expect(model.to_h).not_to have_key(:resource_policy_uri)
      end
    end

    context "when resource_tos_uri is configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_tos_uri = "https://example.com/tos"
      end

      it "includes resource_tos_uri in the response" do
        expect(model.to_h[:resource_tos_uri]).to eq("https://example.com/tos")
      end
    end

    context "when resource_tos_uri is not configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_tos_uri = nil
      end

      it "omits resource_tos_uri from the response" do
        expect(model.to_h).not_to have_key(:resource_tos_uri)
      end
    end
  end
end
