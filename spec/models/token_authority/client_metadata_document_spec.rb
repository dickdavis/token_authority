# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientMetadataDocument, type: :model do
  let(:client_id_url) { "https://example.com/oauth-client" }
  let(:metadata) do
    {
      "client_id" => client_id_url,
      "client_name" => "Example Client",
      "redirect_uris" => ["https://example.com/callback", "https://example.com/callback2"],
      "client_uri" => "https://example.com",
      "logo_uri" => "https://example.com/logo.png",
      "tos_uri" => "https://example.com/tos",
      "policy_uri" => "https://example.com/policy",
      "contacts" => ["contact@example.com"],
      "scope" => "openid profile",
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"],
      "software_id" => "example-software",
      "software_version" => "1.0.0"
    }
  end

  subject(:document) { described_class.new(metadata) }

  describe "#public_id" do
    it "returns the client_id URL" do
      expect(document.public_id).to eq(client_id_url)
    end
  end

  describe "#client_type" do
    it "returns 'public'" do
      expect(document.client_type).to eq("public")
    end
  end

  describe "#public_client_type?" do
    it "returns true" do
      expect(document.public_client_type?).to be true
    end
  end

  describe "#confidential_client_type?" do
    it "returns false" do
      expect(document.confidential_client_type?).to be false
    end
  end

  describe "#name" do
    context "when client_name is present" do
      it "returns the client_name" do
        expect(document.name).to eq("Example Client")
      end
    end

    context "when client_name is not present" do
      let(:metadata) { {"client_id" => client_id_url, "redirect_uris" => ["https://example.com/callback"]} }

      it "returns the client_id" do
        expect(document.name).to eq(client_id_url)
      end
    end
  end

  describe "#redirect_uris" do
    it "returns the redirect_uris array" do
      expect(document.redirect_uris).to eq(["https://example.com/callback", "https://example.com/callback2"])
    end

    context "when redirect_uris is not present" do
      let(:metadata) { {"client_id" => client_id_url} }

      it "returns an empty array" do
        expect(document.redirect_uris).to eq([])
      end
    end
  end

  describe "#redirect_uri_registered?" do
    it "returns true for registered redirect URIs" do
      expect(document.redirect_uri_registered?("https://example.com/callback")).to be true
    end

    it "returns false for unregistered redirect URIs" do
      expect(document.redirect_uri_registered?("https://example.com/other")).to be false
    end
  end

  describe "#primary_redirect_uri" do
    it "returns the first redirect URI" do
      expect(document.primary_redirect_uri).to eq("https://example.com/callback")
    end
  end

  describe "#access_token_duration" do
    it "returns the default access token duration from config" do
      expect(document.access_token_duration).to eq(TokenAuthority.config.rfc_9068_default_access_token_duration)
    end
  end

  describe "#refresh_token_duration" do
    it "returns the default refresh token duration from config" do
      expect(document.refresh_token_duration).to eq(TokenAuthority.config.rfc_9068_default_refresh_token_duration)
    end
  end

  describe "#client_secret" do
    it "returns nil" do
      expect(document.client_secret).to be_nil
    end
  end

  describe "#client_secret_id" do
    it "returns nil" do
      expect(document.client_secret_id).to be_nil
    end
  end

  describe "#authenticate_with_secret" do
    it "returns false for any secret" do
      expect(document.authenticate_with_secret("any-secret")).to be false
    end
  end

  describe "#token_endpoint_auth_method" do
    it "returns 'none'" do
      expect(document.token_endpoint_auth_method).to eq("none")
    end
  end

  describe "#grant_types" do
    it "returns the grant_types from metadata" do
      expect(document.grant_types).to eq(["authorization_code", "refresh_token"])
    end

    context "when grant_types is not present" do
      let(:metadata) { {"client_id" => client_id_url, "redirect_uris" => ["https://example.com/callback"]} }

      it "returns default grant types" do
        expect(document.grant_types).to eq(["authorization_code"])
      end
    end
  end

  describe "#response_types" do
    it "returns the response_types from metadata" do
      expect(document.response_types).to eq(["code"])
    end

    context "when response_types is not present" do
      let(:metadata) { {"client_id" => client_id_url, "redirect_uris" => ["https://example.com/callback"]} }

      it "returns default response types" do
        expect(document.response_types).to eq(["code"])
      end
    end
  end

  describe "#scope" do
    it "returns the scope from metadata" do
      expect(document.scope).to eq("openid profile")
    end
  end

  describe "human-readable metadata accessors" do
    it "returns client_uri" do
      expect(document.client_uri).to eq("https://example.com")
    end

    it "returns logo_uri" do
      expect(document.logo_uri).to eq("https://example.com/logo.png")
    end

    it "returns tos_uri" do
      expect(document.tos_uri).to eq("https://example.com/tos")
    end

    it "returns policy_uri" do
      expect(document.policy_uri).to eq("https://example.com/policy")
    end

    it "returns contacts" do
      expect(document.contacts).to eq(["contact@example.com"])
    end
  end

  describe "technical metadata accessors" do
    it "returns software_id" do
      expect(document.software_id).to eq("example-software")
    end

    it "returns software_version" do
      expect(document.software_version).to eq("1.0.0")
    end
  end

  describe "#url_based?" do
    it "returns true" do
      expect(document.url_based?).to be true
    end
  end

  describe "#new_authorization_grant" do
    let(:user) { create(:user) }
    let(:challenge_params) do
      {
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: "https://example.com/callback"
      }
    end

    it "creates an authorization grant with client_id_url set" do
      grant = document.new_authorization_grant(user: user, challenge_params: challenge_params)

      expect(grant).to be_persisted
      expect(grant.client_id_url).to eq(client_id_url)
      expect(grant.token_authority_client).to be_nil
      expect(grant.user).to eq(user)
    end
  end

  describe "#new_authorization_request" do
    it "creates an authorization request" do
      request = document.new_authorization_request(
        client_id: client_id_url,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: "https://example.com/callback",
        response_type: "code",
        state: "some-state"
      )

      expect(request).to be_a(TokenAuthority::AuthorizationRequest)
      expect(request.token_authority_client).to eq(document)
    end
  end

  describe "#url_for_redirect" do
    it "builds a redirect URL with params" do
      result = document.url_for_redirect(params: {code: "abc123", state: "xyz"})

      expect(result).to eq("https://example.com/callback?code=abc123&state=xyz")
    end

    context "with invalid primary redirect URI" do
      let(:metadata) { {"client_id" => client_id_url, "redirect_uris" => [nil]} }

      it "raises InvalidRedirectUrlError" do
        expect { document.url_for_redirect(params: {code: "abc123"}) }
          .to raise_error(TokenAuthority::InvalidRedirectUrlError)
      end
    end
  end
end
