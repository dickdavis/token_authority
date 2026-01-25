# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::Configuration do
  subject(:config) { described_class.new }

  describe "#protected_resource_for" do
    context "when resources is empty" do
      before { config.resources = {} }

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

    context "when resources is nil" do
      before { config.resources = nil }

      it "returns nil for any resource key" do
        expect(config.protected_resource_for("api")).to be_nil
      end
    end

    context "when resources has one entry" do
      before do
        config.resources = {
          api: {
            resource: "https://api.example.com",
            resource_name: "API"
          }
        }
      end

      it "returns the entry for nil resource key" do
        result = config.protected_resource_for(nil)
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns the entry for blank resource key" do
        result = config.protected_resource_for("")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns the entry for matching symbol key" do
        result = config.protected_resource_for("api")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns the entry (fallback) for non-matching key" do
        result = config.protected_resource_for("unknown")
        expect(result[:resource]).to eq("https://api.example.com")
      end
    end

    context "when resources has multiple entries" do
      before do
        config.resources = {
          api: {
            resource: "https://api.example.com",
            resource_name: "REST API"
          },
          mcp: {
            resource: "https://mcp.example.com",
            resource_name: "MCP Server"
          }
        }
      end

      it "returns first entry for nil resource key" do
        result = config.protected_resource_for(nil)
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns first entry for blank resource key" do
        result = config.protected_resource_for("")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns the matching resource config for 'api'" do
        result = config.protected_resource_for("api")
        expect(result[:resource]).to eq("https://api.example.com")
      end

      it "returns the matching resource config for 'mcp'" do
        result = config.protected_resource_for("mcp")
        expect(result[:resource]).to eq("https://mcp.example.com")
      end

      it "returns first entry (fallback) for unconfigured resource key" do
        result = config.protected_resource_for("unknown")
        expect(result[:resource]).to eq("https://api.example.com")
      end
    end

    context "with string keys passed to lookup" do
      before do
        config.resources = {
          api: {resource: "https://api.example.com"}
        }
      end

      it "converts string to symbol for lookup" do
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
    it "returns false when resources is empty" do
      config.resources = {}
      expect(config.rfc_8707_enabled?).to be false
    end

    it "returns true when resources is configured" do
      config.resources = {
        api: {resource: "https://api.example.com", resource_name: "API"}
      }
      expect(config.rfc_8707_enabled?).to be true
    end
  end

  describe "#resource_registry" do
    context "when resources is empty" do
      before { config.resources = {} }

      it "returns empty hash" do
        expect(config.resource_registry).to eq({})
      end
    end

    context "when resources is nil" do
      before { config.resources = nil }

      it "returns empty hash" do
        expect(config.resource_registry).to eq({})
      end
    end

    context "when resources is configured" do
      before do
        config.resources = {
          api: {resource: "https://api.example.com", resource_name: "REST API"},
          mcp: {resource: "https://mcp.example.com", resource_name: "MCP Server"}
        }
      end

      it "returns mapping from all resource URIs to names" do
        expect(config.resource_registry).to eq({
          "https://api.example.com" => "REST API",
          "https://mcp.example.com" => "MCP Server"
        })
      end
    end

    context "when resource has no resource_name" do
      before do
        config.resources = {
          api: {resource: "https://api.example.com"}
        }
      end

      it "uses the resource URI as the display name" do
        expect(config.resource_registry).to eq({
          "https://api.example.com" => "https://api.example.com"
        })
      end
    end

    context "when resources has invalid entries" do
      before do
        config.resources = {
          api: {resource: "https://api.example.com", resource_name: "REST API"},
          invalid: nil,
          empty: {}
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

    it "raises error when rfc_8707_require_resource is true but no resources configured" do
      config.rfc_8707_require_resource = true
      config.resources = {}

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "rfc_8707_require_resource is true but no protected resources are configured"
      )
    end

    it "raises error when resource entry is missing the :resource field" do
      config.resources = {
        api: {resource_name: "API without resource URI"}
      }

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "resource :api is missing the required :resource field"
      )
    end

    it "raises error when resource entry has blank :resource field" do
      config.resources = {
        api: {resource: "", resource_name: "API"}
      }

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "resource :api is missing the required :resource field"
      )
    end

    it "raises error when resource entry has nil :resource field" do
      config.resources = {
        api: {resource: nil, resource_name: "API"}
      }

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "resource :api is missing the required :resource field"
      )
    end

    it "validates all resources and reports the first invalid one" do
      config.resources = {
        api: {resource: "https://api.example.com"},
        mcp: {resource_name: "MCP without resource URI"}
      }

      expect { config.validate! }.to raise_error(
        TokenAuthority::ConfigurationError,
        "resource :mcp is missing the required :resource field"
      )
    end

    it "does not raise when configuration is valid" do
      config.scopes = {"read" => "Read access"}
      config.require_scope = true
      config.resources = {api: {resource: "https://api.example.com", resource_name: "API"}}
      config.rfc_8707_require_resource = true

      expect { config.validate! }.not_to raise_error
    end

    it "does not raise when resources is empty" do
      config.resources = {}

      expect { config.validate! }.not_to raise_error
    end

    it "does not raise when resources is nil" do
      config.resources = nil

      expect { config.validate! }.not_to raise_error
    end
  end

  describe "default values" do
    it "initializes resources as empty hash" do
      expect(config.resources).to eq({})
    end
  end
end
