# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationGrantsHelper, type: :helper do
  describe "#resource_display_name" do
    let(:resource_uri) { "https://api.example.com" }

    context "when no resources are configured" do
      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return({})
      end

      it "returns the resource URI as-is" do
        expect(helper.resource_display_name(resource_uri)).to eq(resource_uri)
      end
    end

    context "when resources are configured with display names" do
      let(:configured_resources) do
        {
          "https://api.example.com" => "Main API",
          "https://billing.example.com" => "Billing Service"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(configured_resources)
      end

      it "returns the configured display name for a mapped URI" do
        expect(helper.resource_display_name("https://api.example.com")).to eq("Main API")
      end

      it "returns the configured display name for another mapped URI" do
        expect(helper.resource_display_name("https://billing.example.com")).to eq("Billing Service")
      end

      it "returns the URI as-is for an unmapped URI" do
        expect(helper.resource_display_name("https://unknown.example.com")).to eq("https://unknown.example.com")
      end
    end

    context "when resources config is nil" do
      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(nil)
      end

      it "returns the resource URI as-is" do
        expect(helper.resource_display_name(resource_uri)).to eq(resource_uri)
      end
    end
  end

  describe "#scope_display_name" do
    let(:scope) { "read" }

    context "when no scopes are configured" do
      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return({})
      end

      it "returns the scope as-is" do
        expect(helper.scope_display_name(scope)).to eq(scope)
      end
    end

    context "when scopes are configured with display names" do
      let(:configured_scopes) do
        {
          "read" => "Read access",
          "write" => "Write access"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return(configured_scopes)
      end

      it "returns the configured display name for a mapped scope" do
        expect(helper.scope_display_name("read")).to eq("Read access")
      end

      it "returns the configured display name for another mapped scope" do
        expect(helper.scope_display_name("write")).to eq("Write access")
      end

      it "returns the scope as-is for an unmapped scope" do
        expect(helper.scope_display_name("admin")).to eq("admin")
      end
    end

    context "when scopes config is nil" do
      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return(nil)
      end

      it "returns the scope as-is" do
        expect(helper.scope_display_name(scope)).to eq(scope)
      end
    end
  end
end
