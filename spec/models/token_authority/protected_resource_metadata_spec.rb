# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ProtectedResourceMetadata, type: :model do
  let!(:original_config) do
    {
      rfc_9068_issuer_url: TokenAuthority.config.rfc_9068_issuer_url,
      protected_resource: TokenAuthority.config.protected_resource,
      protected_resources: TokenAuthority.config.protected_resources
    }
  end

  before do
    TokenAuthority.config.rfc_9068_issuer_url = "https://example.com/"
    TokenAuthority.config.protected_resource = {}
    TokenAuthority.config.protected_resources = {}
  end

  after do
    original_config.each do |key, value|
      TokenAuthority.config.send("#{key}=", value)
    end
  end

  describe "#to_h" do
    context "when protected_resource is configured" do
      before do
        TokenAuthority.config.protected_resource = {
          resource: "https://api.example.com",
          resource_name: "Example API"
        }
      end

      it "uses protected_resource for blank resource key" do
        metadata = described_class.new(resource: "")
        expect(metadata.to_h[:resource]).to eq("https://api.example.com")
      end

      it "uses protected_resource for nil resource key" do
        metadata = described_class.new(resource: nil)
        expect(metadata.to_h[:resource]).to eq("https://api.example.com")
      end
    end

    context "when protected_resources is configured with resource keys" do
      before do
        TokenAuthority.config.protected_resources = {
          "api" => {
            resource: "https://api.example.com",
            resource_name: "REST API"
          },
          "mcp" => {
            resource: "https://mcp.example.com",
            resource_name: "MCP Server"
          }
        }
      end

      it "uses resource-specific config when key matches" do
        metadata = described_class.new(resource: "api")
        expect(metadata.to_h[:resource]).to eq("https://api.example.com")
      end

      it "returns the correct config for different resource keys" do
        metadata = described_class.new(resource: "mcp")
        expect(metadata.to_h[:resource]).to eq("https://mcp.example.com")
      end
    end

    context "when resource key is present but not configured" do
      before do
        TokenAuthority.config.protected_resource = {
          resource: "https://default.example.com",
          resource_name: "Default API"
        }
        TokenAuthority.config.protected_resources = {
          "api" => {
            resource: "https://api.example.com",
            resource_name: "REST API"
          }
        }
      end

      it "falls back to protected_resource" do
        metadata = described_class.new(resource: "unknown")
        expect(metadata.to_h[:resource]).to eq("https://default.example.com")
      end
    end

    context "when no configuration exists for resource key" do
      before do
        TokenAuthority.config.protected_resource = {}
        TokenAuthority.config.protected_resources = {}
      end

      it "raises ResourceNotConfiguredError" do
        metadata = described_class.new(resource: "unknown")
        expect { metadata.to_h }.to raise_error(TokenAuthority::ResourceNotConfiguredError)
      end
    end

    context "when protected_resource is empty hash" do
      before do
        TokenAuthority.config.protected_resource = {}
      end

      it "raises ResourceNotConfiguredError" do
        metadata = described_class.new(resource: nil)
        expect { metadata.to_h }.to raise_error(TokenAuthority::ResourceNotConfiguredError)
      end
    end

    context "with basic protected_resource configured" do
      subject(:model) { described_class.new(resource: nil) }

      before do
        TokenAuthority.config.protected_resource = {
          resource: "https://api.example.com"
        }
      end

      it "returns the required resource field" do
        expect(model.to_h[:resource]).to eq("https://api.example.com")
      end

      it "returns the authorization_servers field defaulting to issuer" do
        expect(model.to_h[:authorization_servers]).to eq(["https://example.com"])
      end

      context "with custom authorization_servers configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            authorization_servers: [
              "https://auth1.example.com",
              "https://auth2.example.com"
            ]
          }
        end

        it "uses the configured authorization_servers" do
          expect(model.to_h[:authorization_servers]).to eq([
            "https://auth1.example.com",
            "https://auth2.example.com"
          ])
        end
      end

      context "when scopes_supported is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            scopes_supported: ["api:read", "api:write"]
          }
        end

        it "includes scopes_supported in the response" do
          expect(model.to_h[:scopes_supported]).to eq(["api:read", "api:write"])
        end
      end

      context "when scopes_supported is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits scopes_supported from the response" do
          expect(model.to_h).not_to have_key(:scopes_supported)
        end
      end

      context "when bearer_methods_supported is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            bearer_methods_supported: ["header", "body"]
          }
        end

        it "includes bearer_methods_supported in the response" do
          expect(model.to_h[:bearer_methods_supported]).to eq(["header", "body"])
        end
      end

      context "when bearer_methods_supported is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits bearer_methods_supported from the response" do
          expect(model.to_h).not_to have_key(:bearer_methods_supported)
        end
      end

      context "when jwks_uri is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            jwks_uri: "https://example.com/.well-known/jwks.json"
          }
        end

        it "includes jwks_uri in the response" do
          expect(model.to_h[:jwks_uri]).to eq("https://example.com/.well-known/jwks.json")
        end
      end

      context "when jwks_uri is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits jwks_uri from the response" do
          expect(model.to_h).not_to have_key(:jwks_uri)
        end
      end

      context "when resource_name is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            resource_name: "Example API"
          }
        end

        it "includes resource_name in the response" do
          expect(model.to_h[:resource_name]).to eq("Example API")
        end
      end

      context "when resource_name is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits resource_name from the response" do
          expect(model.to_h).not_to have_key(:resource_name)
        end
      end

      context "when resource_documentation is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            resource_documentation: "https://example.com/docs/api"
          }
        end

        it "includes resource_documentation in the response" do
          expect(model.to_h[:resource_documentation]).to eq("https://example.com/docs/api")
        end
      end

      context "when resource_documentation is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits resource_documentation from the response" do
          expect(model.to_h).not_to have_key(:resource_documentation)
        end
      end

      context "when resource_policy_uri is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            resource_policy_uri: "https://example.com/privacy"
          }
        end

        it "includes resource_policy_uri in the response" do
          expect(model.to_h[:resource_policy_uri]).to eq("https://example.com/privacy")
        end
      end

      context "when resource_policy_uri is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits resource_policy_uri from the response" do
          expect(model.to_h).not_to have_key(:resource_policy_uri)
        end
      end

      context "when resource_tos_uri is configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com",
            resource_tos_uri: "https://example.com/tos"
          }
        end

        it "includes resource_tos_uri in the response" do
          expect(model.to_h[:resource_tos_uri]).to eq("https://example.com/tos")
        end
      end

      context "when resource_tos_uri is not configured" do
        before do
          TokenAuthority.config.protected_resource = {
            resource: "https://api.example.com"
          }
        end

        it "omits resource_tos_uri from the response" do
          expect(model.to_h).not_to have_key(:resource_tos_uri)
        end
      end
    end
  end
end
