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
end
