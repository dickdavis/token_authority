# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::SoftwareStatement, type: :model do
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:kid) { "test-key-1" }

  let(:jwks) do
    {
      keys: [
        {
          kty: "RSA",
          kid: kid,
          use: "sig",
          alg: "RS256",
          n: Base64.urlsafe_encode64(rsa_key.n.to_s(2), padding: false),
          e: Base64.urlsafe_encode64(rsa_key.e.to_s(2), padding: false)
        }
      ]
    }
  end

  let(:payload) do
    {
      iss: "https://software-publisher.example.com",
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      redirect_uris: ["https://app.example.com/callback"],
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "Test Application",
      client_uri: "https://app.example.com",
      logo_uri: "https://app.example.com/logo.png",
      scope: "read write",
      contacts: ["admin@example.com"],
      tos_uri: "https://app.example.com/tos",
      policy_uri: "https://app.example.com/privacy",
      software_id: "app-12345",
      software_version: "1.0.0"
    }
  end

  let(:signed_jwt) do
    JWT.encode(payload, rsa_key, "RS256", {kid: kid, typ: "JWT"})
  end

  let(:unsigned_jwt) do
    JWT.encode(payload, nil, "none")
  end

  describe ".decode" do
    it "decodes a JWT without verification" do
      statement = described_class.decode(signed_jwt)

      expect(statement).to be_a(described_class)
      expect(statement.client_name).to eq("Test Application")
    end

    it "decodes an unsigned JWT" do
      statement = described_class.decode(unsigned_jwt)

      expect(statement.client_name).to eq("Test Application")
    end

    it "marks the statement as not trusted" do
      statement = described_class.decode(signed_jwt)

      expect(statement.trusted?).to be false
    end

    it "stores the raw JWT" do
      statement = described_class.decode(signed_jwt)

      expect(statement.raw_jwt).to eq(signed_jwt)
    end

    context "with an invalid JWT" do
      it "raises InvalidSoftwareStatementError" do
        expect { described_class.decode("not.a.jwt") }
          .to raise_error(TokenAuthority::InvalidSoftwareStatementError)
      end
    end

    context "with a malformed JWT" do
      it "raises InvalidSoftwareStatementError" do
        expect { described_class.decode("totally invalid") }
          .to raise_error(TokenAuthority::InvalidSoftwareStatementError)
      end
    end
  end

  describe ".decode_and_verify" do
    it "decodes and verifies a signed JWT" do
      statement = described_class.decode_and_verify(signed_jwt, jwks: jwks)

      expect(statement).to be_a(described_class)
      expect(statement.client_name).to eq("Test Application")
    end

    it "marks the statement as trusted" do
      statement = described_class.decode_and_verify(signed_jwt, jwks: jwks)

      expect(statement.trusted?).to be true
    end

    it "accepts a JWT::JWK::Set" do
      jwk_set = JWT::JWK::Set.new(jwks)
      statement = described_class.decode_and_verify(signed_jwt, jwks: jwk_set)

      expect(statement.trusted?).to be true
    end

    context "with an invalid signature" do
      let(:other_key) { OpenSSL::PKey::RSA.generate(2048) }
      let(:wrong_jwks) do
        {
          keys: [
            {
              kty: "RSA",
              kid: kid,
              use: "sig",
              alg: "RS256",
              n: Base64.urlsafe_encode64(other_key.n.to_s(2), padding: false),
              e: Base64.urlsafe_encode64(other_key.e.to_s(2), padding: false)
            }
          ]
        }
      end

      it "raises InvalidSoftwareStatementError" do
        expect { described_class.decode_and_verify(signed_jwt, jwks: wrong_jwks) }
          .to raise_error(TokenAuthority::InvalidSoftwareStatementError)
      end
    end

    context "with an unsigned JWT" do
      it "raises InvalidSoftwareStatementError" do
        expect { described_class.decode_and_verify(unsigned_jwt, jwks: jwks) }
          .to raise_error(TokenAuthority::InvalidSoftwareStatementError)
      end
    end
  end

  describe "claim accessors" do
    subject(:statement) { described_class.decode(signed_jwt) }

    it "provides accessors for all standard claims" do
      aggregate_failures do
        expect(statement.redirect_uris).to eq(["https://app.example.com/callback"])
        expect(statement.token_endpoint_auth_method).to eq("client_secret_basic")
        expect(statement.grant_types).to eq(["authorization_code", "refresh_token"])
        expect(statement.response_types).to eq(["code"])
        expect(statement.client_name).to eq("Test Application")
        expect(statement.client_uri).to eq("https://app.example.com")
        expect(statement.logo_uri).to eq("https://app.example.com/logo.png")
        expect(statement.scope).to eq("read write")
        expect(statement.contacts).to eq(["admin@example.com"])
        expect(statement.tos_uri).to eq("https://app.example.com/tos")
        expect(statement.policy_uri).to eq("https://app.example.com/privacy")
        expect(statement.software_id).to eq("app-12345")
        expect(statement.software_version).to eq("1.0.0")
      end
    end

    context "with missing claims" do
      let(:minimal_payload) { {client_name: "Minimal App"} }
      let(:minimal_jwt) { JWT.encode(minimal_payload, rsa_key, "RS256", {kid: kid}) }

      subject(:statement) { described_class.decode(minimal_jwt) }

      it "returns nil for missing claims" do
        aggregate_failures do
          expect(statement.client_name).to eq("Minimal App")
          expect(statement.redirect_uris).to be_nil
          expect(statement.software_id).to be_nil
        end
      end
    end
  end

  describe "#claims" do
    subject(:statement) { described_class.decode(signed_jwt) }

    it "returns a hash of standard claims only" do
      claims = statement.claims

      aggregate_failures do
        expect(claims[:client_name]).to eq("Test Application")
        expect(claims[:redirect_uris]).to eq(["https://app.example.com/callback"])
        expect(claims[:software_id]).to eq("app-12345")
      end
    end

    it "excludes non-standard claims" do
      claims = statement.claims

      expect(claims).not_to have_key(:iss)
      expect(claims).not_to have_key(:iat)
      expect(claims).not_to have_key(:exp)
    end
  end

  describe "#trusted?" do
    context "when decoded without verification" do
      subject(:statement) { described_class.decode(signed_jwt) }

      it "returns false" do
        expect(statement.trusted?).to be false
      end
    end

    context "when decoded with verification" do
      subject(:statement) { described_class.decode_and_verify(signed_jwt, jwks: jwks) }

      it "returns true" do
        expect(statement.trusted?).to be true
      end
    end
  end

  describe "#to_h" do
    subject(:statement) { described_class.decode(signed_jwt) }

    it "returns the same as #claims" do
      expect(statement.to_h).to eq(statement.claims)
    end
  end

  describe "#header" do
    subject(:statement) { described_class.decode(signed_jwt) }

    it "provides access to JWT header" do
      expect(statement.header[:kid]).to eq(kid)
      expect(statement.header[:typ]).to eq("JWT")
    end
  end

  describe "#payload" do
    subject(:statement) { described_class.decode(signed_jwt) }

    it "provides access to full JWT payload" do
      expect(statement.payload[:iss]).to eq("https://software-publisher.example.com")
      expect(statement.payload[:client_name]).to eq("Test Application")
    end
  end
end
