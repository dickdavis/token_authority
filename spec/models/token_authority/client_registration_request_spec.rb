# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientRegistrationRequest, type: :model do
  subject(:request) { described_class.new(attrs) }

  let(:attrs) do
    {
      redirect_uris: ["https://example.com/callback"],
      client_name: "Test Client"
    }
  end

  describe "validations" do
    describe "redirect_uris" do
      it "is valid with valid HTTP URIs" do
        request.redirect_uris = ["http://localhost:3000/callback"]
        expect(request).to be_valid
      end

      it "is valid with valid HTTPS URIs" do
        request.redirect_uris = ["https://example.com/callback"]
        expect(request).to be_valid
      end

      it "is invalid when blank" do
        request.redirect_uris = nil
        expect(request).not_to be_valid
        expect(request.errors[:redirect_uris]).to be_present
      end

      it "is invalid with non-HTTP URIs" do
        request.redirect_uris = ["ftp://example.com/callback"]
        expect(request).not_to be_valid
        expect(request.errors[:redirect_uris]).to be_present
      end

      it "is invalid with malformed URIs" do
        request.redirect_uris = ["not a uri"]
        expect(request).not_to be_valid
        expect(request.errors[:redirect_uris]).to be_present
      end
    end

    describe "token_endpoint_auth_method" do
      it "defaults to client_secret_basic" do
        expect(request.token_endpoint_auth_method).to eq("client_secret_basic")
      end

      it "is valid with allowed methods" do
        %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt].each do |method|
          request.token_endpoint_auth_method = method
          request.jwks = {"keys" => []} if method == "private_key_jwt"
          expect(request).to be_valid
        end
      end
    end

    describe "grant_types" do
      it "defaults to authorization_code" do
        expect(request.grant_types).to eq(["authorization_code"])
      end

      it "is invalid with disallowed grant types" do
        request.grant_types = ["password"]
        expect(request).not_to be_valid
        expect(request.errors[:grant_types]).to be_present
      end
    end

    describe "response_types" do
      it "defaults to code" do
        expect(request.response_types).to eq(["code"])
      end

      it "is invalid when grant_types includes authorization_code but response_types excludes code" do
        request.grant_types = ["authorization_code"]
        request.response_types = ["token"]
        expect(request).not_to be_valid
        expect(request.errors[:response_types]).to be_present
      end
    end

    describe "contacts" do
      it "is valid with valid email addresses" do
        request.contacts = ["admin@example.com", "support@example.com"]
        expect(request).to be_valid
      end

      it "is invalid with invalid email addresses" do
        request.contacts = ["not-an-email"]
        expect(request).not_to be_valid
        expect(request.errors[:contacts]).to be_present
      end
    end

    describe "jwks and jwks_uri" do
      it "is invalid when both jwks and jwks_uri are provided" do
        request.jwks = {"keys" => []}
        request.jwks_uri = "https://example.com/.well-known/jwks.json"
        expect(request).not_to be_valid
        expect(request.errors[:base]).to be_present
      end

      it "is invalid when private_key_jwt is used without jwks or jwks_uri" do
        request.token_endpoint_auth_method = "private_key_jwt"
        request.jwks = nil
        request.jwks_uri = nil
        expect(request).not_to be_valid
        expect(request.errors[:base]).to be_present
      end

      it "is valid when private_key_jwt is used with jwks" do
        request.token_endpoint_auth_method = "private_key_jwt"
        request.jwks = {"keys" => []}
        expect(request).to be_valid
      end

      it "is valid when private_key_jwt is used with jwks_uri" do
        request.token_endpoint_auth_method = "private_key_jwt"
        request.jwks_uri = "https://example.com/.well-known/jwks.json"
        expect(request).to be_valid
      end
    end
  end

  describe "#create_client!" do
    it "creates a client with the provided attributes" do
      client = request.create_client!

      aggregate_failures do
        expect(client).to be_persisted
        expect(client.name).to eq("Test Client")
        expect(client.redirect_uris).to eq(["https://example.com/callback"])
        expect(client.dynamically_registered).to be true
      end
    end

    it "creates a confidential client by default" do
      client = request.create_client!
      expect(client.client_type).to eq("confidential")
    end

    it "creates a public client when token_endpoint_auth_method is none" do
      request.token_endpoint_auth_method = "none"
      client = request.create_client!
      expect(client.client_type).to eq("public")
    end

    it "raises InvalidClientMetadataError when invalid" do
      request.redirect_uris = nil
      expect { request.create_client! }.to raise_error(TokenAuthority::InvalidClientMetadataError)
    end
  end
end
