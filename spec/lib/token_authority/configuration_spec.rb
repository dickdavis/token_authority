# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::Configuration do
  subject(:config) { described_class.new }

  describe "#protected_resource_for" do
    context "when neither protected_resource nor protected_resources is configured" do
      before do
        config.protected_resource = {}
        config.protected_resources = {}
      end

      it "returns nil for nil resource key" do
        expect(config.protected_resource_for(nil)).to be_nil
      end

      it "returns nil for blank resource key" do
        expect(config.protected_resource_for("")).to be_nil
      end

      it "returns nil for any resource key" do
        expect(config.protected_resource_for("api")).to be_nil
      end
    end

    context "when only protected_resource is configured" do
      before do
        config.protected_resource = {
          resource: "https://api.example.com",
          resource_name: "Default API"
        }
        config.protected_resources = {}
      end

      it "returns protected_resource for nil resource key" do
        result = config.protected_resource_for(nil)
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns protected_resource for blank resource key" do
        result = config.protected_resource_for("")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns protected_resource for any resource key (as fallback)" do
        result = config.protected_resource_for("unknown")
        expect(result[:resource]).to eq("https://api.example.com")
      end
    end

    context "when only protected_resources is configured" do
      before do
        config.protected_resource = {}
        config.protected_resources = {
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

      it "returns nil for nil resource key" do
        expect(config.protected_resource_for(nil)).to be_nil
      end

      it "returns nil for blank resource key" do
        expect(config.protected_resource_for("")).to be_nil
      end

      it "returns the matching resource config" do
        result = config.protected_resource_for("api")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns the correct config for different resource keys" do
        result = config.protected_resource_for("mcp")
        expect(result[:resource]).to eq("https://mcp.example.com")
      end

      it "returns nil for unconfigured resource key" do
        expect(config.protected_resource_for("unknown")).to be_nil
      end
    end

    context "when both protected_resource and protected_resources are configured" do
      before do
        config.protected_resource = {
          resource: "https://default.example.com",
          resource_name: "Default API"
        }
        config.protected_resources = {
          "api" => {
            resource: "https://api.example.com",
            resource_name: "REST API"
          }
        }
      end

      it "returns protected_resource for nil resource key" do
        result = config.protected_resource_for(nil)
        expect(result[:resource]).to eq("https://default.example.com")
      end

      it "returns protected_resource for blank resource key" do
        result = config.protected_resource_for("")
        expect(result[:resource]).to eq("https://default.example.com")
      end

      it "returns resource-specific config when available" do
        result = config.protected_resource_for("api")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "falls back to protected_resource for unconfigured resource key" do
        result = config.protected_resource_for("unknown")
        expect(result[:resource]).to eq("https://default.example.com")
      end
    end

    context "when protected_resources is nil" do
      before do
        config.protected_resource = {
          resource: "https://api.example.com"
        }
        config.protected_resources = nil
      end

      it "returns protected_resource for any resource key" do
        result = config.protected_resource_for("api")
        expect(result[:resource]).to eq("https://api.example.com")
      end
    end
  end

  describe "#scopes_enabled?" do
    it "returns false when scopes is nil" do
      config.scopes = nil
      expect(config.scopes_enabled?).to be false
    end

    it "returns false when scopes is empty hash" do
      config.scopes = {}
      expect(config.scopes_enabled?).to be false
    end

    it "returns true when scopes has entries" do
      config.scopes = {"read" => "Read access"}
      expect(config.scopes_enabled?).to be true
    end
  end

  describe "#rfc_8707_enabled?" do
    it "returns false when no protected resources are configured" do
      config.protected_resource = {}
      config.protected_resources = {}
      expect(config.rfc_8707_enabled?).to be false
    end

    it "returns true when protected_resource is configured" do
      config.protected_resource = {resource: "https://api.example.com", resource_name: "API"}
      expect(config.rfc_8707_enabled?).to be true
    end

    it "returns true when protected_resources is configured" do
      config.protected_resources = {
        "api" => {resource: "https://api.example.com", resource_name: "API"}
      }
      expect(config.rfc_8707_enabled?).to be true
    end
  end

  describe "#resource_registry" do
    context "when no protected resources are configured" do
      before do
        config.protected_resource = {}
        config.protected_resources = {}
      end

      it "returns empty hash" do
        expect(config.resource_registry).to eq({})
      end
    end

    context "when protected_resource is configured" do
      before do
        config.protected_resource = {
          resource: "https://api.example.com",
          resource_name: "Main API"
        }
      end

      it "returns mapping from resource URI to name" do
        expect(config.resource_registry).to eq({
          "https://api.example.com" => "Main API"
        })
      end
    end

    context "when protected_resource has no resource_name" do
      before do
        config.protected_resource = {
          resource: "https://api.example.com"
        }
      end

      it "uses the resource URI as the display name" do
        expect(config.resource_registry).to eq({
          "https://api.example.com" => "https://api.example.com"
        })
      end
    end

    context "when protected_resources is configured" do
      before do
        config.protected_resources = {
          "api" => {resource: "https://api.example.com", resource_name: "REST API"},
          "mcp" => {resource: "https://mcp.example.com", resource_name: "MCP Server"}
        }
      end

      it "returns mapping from all resource URIs to names" do
        expect(config.resource_registry).to eq({
          "https://api.example.com" => "REST API",
          "https://mcp.example.com" => "MCP Server"
        })
      end
    end

    context "when both protected_resource and protected_resources are configured" do
      before do
        config.protected_resource = {
          resource: "https://default.example.com",
          resource_name: "Default API"
        }
        config.protected_resources = {
          "api" => {resource: "https://api.example.com", resource_name: "REST API"}
        }
      end

      it "includes all resources in the registry" do
        expect(config.resource_registry).to eq({
          "https://default.example.com" => "Default API",
          "https://api.example.com" => "REST API"
        })
      end
    end

    context "when protected_resources has invalid entries" do
      before do
        config.protected_resources = {
          "api" => {resource: "https://api.example.com", resource_name: "REST API"},
          "invalid" => nil,
          "empty" => {}
        }
      end

      it "skips invalid entries" do
        expect(config.resource_registry).to eq({
          "https://api.example.com" => "REST API"
        })
      end
    end
  end

  describe "#validate!" do
    it "raises error when require_scope is true but scopes not configured" do
      config.require_scope = true
      config.scopes = nil

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "require_scope is true but no scopes are configured"
      )
    end

    it "raises error when rfc_8707_require_resource is true but no protected resources configured" do
      config.rfc_8707_require_resource = true
      config.protected_resource = {}
      config.protected_resources = {}

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "rfc_8707_require_resource is true but no protected resources are configured"
      )
    end

    it "does not raise when configuration is valid" do
      config.scopes = {"read" => "Read access"}
      config.require_scope = true
      config.protected_resource = {resource: "https://api.example.com", resource_name: "API"}
      config.rfc_8707_require_resource = true

      expect { config.validate! }.not_to raise_error
    end
  end

  describe "default values" do
    it "initializes protected_resource as empty hash" do
      expect(config.protected_resource).to eq({})
    end

    it "initializes protected_resources as empty hash" do
      expect(config.protected_resources).to eq({})
    end
  end
end
