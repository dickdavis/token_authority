# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::RefreshToken, type: :model do
  subject(:model) { build(:token_authority_refresh_token, token_authority_session:) }

  let_it_be(:user) { create(:user) }
  let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:) }
  let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

  it_behaves_like "a model that validates token claims"

  describe "callbacks" do
    describe "#expire_token_authority_session" do
      context "when the `exp` claim is blank" do
        it "updates the Session status to `expired`" do
          model.exp = ""
          expect do
            model.valid?
            token_authority_session.reload
          end.to change(token_authority_session, :status).from("created").to("expired")
        end
      end

      context "when the `exp` claim is expired" do
        it "updates the Session status to `expired`" do
          model.exp = 5.minutes.ago.to_i
          expect do
            model.valid?
            token_authority_session.reload
          end.to change(token_authority_session, :status).from("created").to("expired")
        end
      end

      context "when the `exp` is invalid and a revocable claim is also invalid" do
        it "does not update the Session status to `expired`" do
          model.exp = ""
          model.aud = ""
          model.valid?
          expect(token_authority_session.reload).not_to be_expired_status
        end

        it "updates the Session status to `revoked`" do
          model.exp = ""
          model.aud = ""
          expect do
            model.valid?
            token_authority_session.reload
          end.to change(token_authority_session, :status).from("created").to("revoked")
        end
      end
    end
  end

  describe ".default" do
    let(:exp) { 1.hour.from_now.to_i }

    it "returns a refresh token with default claims" do
      refresh_token = described_class.default(exp:)
      aggregate_failures do
        expect(refresh_token).to be_a(described_class)
        expect(refresh_token.aud).to eq(TokenAuthority.config.audience_url)
        expect(refresh_token.exp).to eq(exp)
        expect(refresh_token.iat).to be_a(Integer)
        expect(refresh_token.iss).to eq(TokenAuthority.config.issuer_url)
        expect(refresh_token.jti).to match(TokenAuthority::Session::VALID_UUID_REGEX)
      end
    end

    context "with resources parameter (RFC 8707)" do
      context "when resources is empty" do
        it "uses the configured audience URL" do
          refresh_token = described_class.default(exp:, resources: [])
          expect(refresh_token.aud).to eq(TokenAuthority.config.audience_url)
        end
      end

      context "when resources has a single value" do
        it "sets aud to that single value as a string" do
          refresh_token = described_class.default(exp:, resources: ["https://api.example.com"])
          expect(refresh_token.aud).to eq("https://api.example.com")
        end
      end

      context "when resources has multiple values" do
        it "sets aud to the array of resources" do
          resources = ["https://api1.example.com", "https://api2.example.com"]
          refresh_token = described_class.default(exp:, resources:)
          expect(refresh_token.aud).to eq(resources)
        end
      end
    end

    context "with scopes parameter" do
      context "when scopes is empty" do
        it "does not set scope claim" do
          refresh_token = described_class.default(exp:, scopes: [])
          expect(refresh_token.scope).to be_nil
        end
      end

      context "when scopes is provided" do
        it "sets scope as space-delimited string" do
          refresh_token = described_class.default(exp:, scopes: ["read", "write"])
          expect(refresh_token.scope).to eq("read write")
        end
      end

      context "when scopes has a single value" do
        it "sets scope to that single value" do
          refresh_token = described_class.default(exp:, scopes: ["read"])
          expect(refresh_token.scope).to eq("read")
        end
      end
    end
  end

  describe ".from_token" do
    let(:token) { TokenAuthority::JsonWebToken.encode(model.to_h) }

    it "returns a model" do
      expect(described_class.from_token(token)).to be_a(described_class)
    end
  end

  describe "#to_h" do
    it "returns the model attributes" do
      expect(model.to_h).to eq(
        {
          aud: model.aud,
          exp: model.exp,
          iat: model.iat,
          iss: model.iss,
          jti: model.jti
        }
      )
    end

    context "when scope is present" do
      let(:model_with_scope) do
        described_class.default(
          exp: 1.hour.from_now.to_i,
          scopes: ["read", "write"]
        )
      end

      it "includes scope in the hash" do
        expect(model_with_scope.to_h[:scope]).to eq("read write")
      end
    end
  end

  describe "#to_encoded_token" do
    it "returns the encoded token" do
      expect(model.to_encoded_token).to eq(TokenAuthority::JsonWebToken.encode(model.to_h, model.exp))
    end
  end
end
