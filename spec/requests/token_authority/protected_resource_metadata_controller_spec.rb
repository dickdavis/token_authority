# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ProtectedResourceMetadataController, type: :request do
  describe "GET /.well-known/oauth-protected-resource" do
    subject(:call_endpoint) { get "/.well-known/oauth-protected-resource" }

    let!(:original_config) do
      {
        rfc_9068_issuer_url: TokenAuthority.config.rfc_9068_issuer_url,
        resources: TokenAuthority.config.resources
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

    context "when resources is configured" do
      before do
        TokenAuthority.config.resources = {
          api: {
            resource: "http://localhost:3000/api/",
            resource_name: "Demo API",
            scopes_supported: %w[read write]
          }
        }
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
          expect(body["resource"]).to eq("http://localhost:3000/api/")
          expect(body["authorization_servers"]).to eq(["http://localhost:3000"])
        end
      end

      it "includes configured scopes_supported" do
        call_endpoint
        expect(response.parsed_body["scopes_supported"]).to eq(["read", "write"])
      end

      it "includes configured resource_name" do
        call_endpoint
        expect(response.parsed_body["resource_name"]).to eq("Demo API")
      end
    end

    context "when resources includes resource_documentation" do
      before do
        TokenAuthority.config.resources = {
          api: {
            resource: "http://localhost:3000/api/",
            resource_documentation: "https://example.com/docs"
          }
        }
      end

      it "includes resource_documentation in the response" do
        call_endpoint
        expect(response.parsed_body["resource_documentation"]).to eq("https://example.com/docs")
      end
    end

    context "when resources is empty" do
      before do
        TokenAuthority.config.resources = {}
      end

      it "responds with HTTP status not_found" do
        call_endpoint
        expect(response).to have_http_status(:not_found)
      end
    end
  end
end
