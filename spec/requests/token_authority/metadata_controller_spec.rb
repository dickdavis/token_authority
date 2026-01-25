# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::MetadataController, type: :request do
  describe "GET /.well-known/oauth-authorization-server" do
    subject(:call_endpoint) { get "/.well-known/oauth-authorization-server" }

    let!(:original_issuer_url) { TokenAuthority.config.token_issuer_url }

    before do
      TokenAuthority.config.token_issuer_url = "http://localhost:3000/"
    end

    after do
      TokenAuthority.config.token_issuer_url = original_issuer_url
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
        expect(body["issuer"]).to eq("http://localhost:3000")
        expect(body["authorization_endpoint"]).to eq("http://localhost:3000/oauth/authorize")
        expect(body["token_endpoint"]).to eq("http://localhost:3000/oauth/token")
        expect(body["revocation_endpoint"]).to eq("http://localhost:3000/oauth/revoke")
        expect(body["response_types_supported"]).to eq(["code"])
        expect(body["grant_types_supported"]).to eq(["authorization_code", "refresh_token"])
        expect(body["token_endpoint_auth_methods_supported"]).to eq(TokenAuthority.config.dcr_allowed_token_endpoint_auth_methods)
        expect(body["code_challenge_methods_supported"]).to eq(["S256"])
      end
    end

    context "when scopes is configured" do
      before do
        TokenAuthority.config.scopes = {"read" => "Read access", "write" => "Write access"}
      end

      after do
        TokenAuthority.config.scopes = nil
      end

      it "includes scopes_supported in the response" do
        call_endpoint
        expect(response.parsed_body["scopes_supported"]).to eq(["read", "write"])
      end
    end

    context "when service_documentation is configured" do
      before do
        TokenAuthority.config.authorization_server_documentation = "https://example.com/docs"
      end

      after do
        TokenAuthority.config.authorization_server_documentation = nil
      end

      it "includes service_documentation in the response" do
        call_endpoint
        expect(response.parsed_body["service_documentation"]).to eq("https://example.com/docs")
      end
    end
  end
end
