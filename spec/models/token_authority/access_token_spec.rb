# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AccessToken, type: :model do
  subject(:model) { build(:token_authority_access_token, token_authority_session:) }

  let_it_be(:user) { create(:user) }
  let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:) }
  let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

  it_behaves_like "a model that validates token claims"

  describe "validations" do
    it { is_expected.to validate_presence_of(:user_id) }

    it "adds an error if the provided `user_id` claim does not map to the original authorization grant" do
      other_user = create(:user)
      model.user_id = other_user.id
      model.valid?
      expect(model.errors).to include(:user_id)
    end
  end

  describe "callbacks" do
    describe "#revoke_token_authority_session" do
      context "when the `user_id` claim is invalid" do
        it "updates the Session status to `revoked`" do
          model.user_id = ""
          expect do
            model.valid?
            token_authority_session.reload
          end.to change(token_authority_session, :status).from("created").to("revoked")
        end
      end
    end
  end

  describe ".default" do
    let(:user_id) { "123" }
    let(:exp) { 1.hour.from_now.to_i }

    it "returns an access token with default claims" do
      refresh_token = described_class.default(exp:, user_id:)
      aggregate_failures do
        expect(refresh_token).to be_a(described_class)
        expect(refresh_token.aud).to eq(TokenAuthority.config.audience_url)
        expect(refresh_token.exp).to eq(exp)
        expect(refresh_token.iat).to be_a(Integer)
        expect(refresh_token.iss).to eq(TokenAuthority.config.issuer_url)
        expect(refresh_token.jti).to match(TokenAuthority::Session::VALID_UUID_REGEX)
        expect(refresh_token.user_id).to eq(user_id)
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
          jti: model.jti,
          user_id: model.user_id
        }
      )
    end
  end

  describe "#to_encoded_token" do
    it "returns the encoded token" do
      expect(model.to_encoded_token).to eq(TokenAuthority::JsonWebToken.encode(model.to_h, model.exp))
    end
  end
end
