# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ResourceMetadataController, type: :request do
  describe "GET /.well-known/oauth-protected-resource" do
    subject(:call_endpoint) { get "/.well-known/oauth-protected-resource" }

    let!(:original_config) do
      {
        rfc_9068_issuer_url: TokenAuthority.config.rfc_9068_issuer_url,
        scopes: TokenAuthority.config.scopes,
        rfc_9728_resource: TokenAuthority.config.rfc_9728_resource,
        rfc_9728_scopes_supported: TokenAuthority.config.rfc_9728_scopes_supported,
        rfc_9728_authorization_servers: TokenAuthority.config.rfc_9728_authorization_servers,
        rfc_9728_bearer_methods_supported: TokenAuthority.config.rfc_9728_bearer_methods_supported,
        rfc_9728_resource_name: TokenAuthority.config.rfc_9728_resource_name,
        rfc_9728_resource_documentation: TokenAuthority.config.rfc_9728_resource_documentation
      }
    end

    before do
      TokenAuthority.config.rfc_9068_issuer_url = "http://localhost:3000/"
    end

    after do
      original_config.each do |key, value|
        TokenAuthority.config.send("#{key}=", value)
      end
    end

    it "responds with HTTP status ok" do
      call_endpoint
      expect(response).to have_http_status(:ok)
    end

    it "responds with JSON content type" do
      call_endpoint
      expect(response.content_type).to include("application/json")
    end

    it "responds with the required metadata fields" do
      call_endpoint
      body = response.parsed_body

      aggregate_failures do
        expect(body["resource"]).to eq("http://localhost:3000")
        expect(body["authorization_servers"]).to eq(["http://localhost:3000"])
      end
    end

    context "when scopes_supported is configured" do
      before do
        TokenAuthority.config.rfc_9728_scopes_supported = ["api:read", "api:write"]
      end

      it "includes scopes_supported in the response" do
        call_endpoint
        expect(response.parsed_body["scopes_supported"]).to eq(["api:read", "api:write"])
      end
    end

    context "when resource_name is configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_name = "Example API"
      end

      it "includes resource_name in the response" do
        call_endpoint
        expect(response.parsed_body["resource_name"]).to eq("Example API")
      end
    end

    context "when resource_documentation is configured" do
      before do
        TokenAuthority.config.rfc_9728_resource_documentation = "https://example.com/docs"
      end

      it "includes resource_documentation in the response" do
        call_endpoint
        expect(response.parsed_body["resource_documentation"]).to eq("https://example.com/docs")
      end
    end
  end
end
