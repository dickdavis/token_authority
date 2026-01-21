# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::Client, type: :model do
  subject(:model) { build(:token_authority_client) }

  describe "validations" do
    describe "name" do
      it "validates value is provided and within length constraints" do
        aggregate_failures do
          expect(model).to validate_presence_of(:name)
          expect(model).to validate_length_of(:name).is_at_least(3)
          expect(model).to validate_length_of(:name).is_at_most(255)
        end
      end
    end

    describe "client_type" do
      it "validates values for client_type" do
        aggregate_failures do
          expect(model).to allow_value("public").for(:client_type)
          expect(model).to allow_value("confidential").for(:client_type)
        end
      end

      it "raises an ArgumentError when an invalid client_type is provided" do
        expect { model.client_type = "foobar" }.to raise_error(ArgumentError)
      end
    end

    describe "access_token_duration" do
      it "validates value is an integer greater than 0" do
        aggregate_failures do
          expect(model).to validate_numericality_of(:access_token_duration).only_integer
          expect(model).to validate_numericality_of(:access_token_duration).is_greater_than(0)
        end
      end
    end

    describe "refresh_token_duration" do
      it "validates value is an integer greater than 0" do
        aggregate_failures do
          expect(model).to validate_numericality_of(:refresh_token_duration).only_integer
          expect(model).to validate_numericality_of(:refresh_token_duration).is_greater_than(0)
        end
      end
    end

    describe "redirection_uris" do
      it { is_expected.to validate_presence_of(:redirect_uris) }

      it "adds an error if redirect_uris contains an invalid URI" do
        model.redirect_uris = ["foobar"]
        model.valid?
        expect(model.errors).to include(:redirect_uris)
      end

      it "does not add an error if redirect_uris contains valid URIs" do
        model.redirect_uris = ["http://localhost:3000/", "https://example.com/callback"]
        model.valid?
        expect(model.errors).not_to include(:redirect_uris)
      end
    end

    describe "token_endpoint_auth_method" do
      it "validates inclusion in SUPPORTED_AUTH_METHODS" do
        aggregate_failures do
          expect(model).to allow_value("none").for(:token_endpoint_auth_method)
          expect(model).to allow_value("client_secret_basic").for(:token_endpoint_auth_method)
          expect(model).to allow_value("client_secret_post").for(:token_endpoint_auth_method)
          expect(model).to allow_value("client_secret_jwt").for(:token_endpoint_auth_method)
          expect(model).to allow_value("private_key_jwt").for(:token_endpoint_auth_method)
          expect(model).not_to allow_value("invalid_method").for(:token_endpoint_auth_method)
        end
      end
    end

    describe "jwks requirement for private_key_jwt" do
      before { model.token_endpoint_auth_method = "private_key_jwt" }

      it "is invalid without jwks or jwks_uri" do
        model.jwks = nil
        model.jwks_uri = nil
        model.valid?
        expect(model.errors[:base]).to be_present
      end

      it "is valid with jwks" do
        model.jwks = {"keys" => []}
        model.valid?
        expect(model.errors[:base]).to be_empty
      end

      it "is valid with jwks_uri" do
        model.jwks_uri = "https://example.com/.well-known/jwks.json"
        model.valid?
        expect(model.errors[:base]).to be_empty
      end
    end
  end

  describe "callbacks" do
    describe "#generate_client_secret_id" do
      context "when client type is confidential" do
        it "generates a client secret ID when a new client is created" do
          expect { model.save! }.to change(model, :client_secret_id).from(nil).to(be_present)
        end
      end

      context "when client type is public" do
        it "does not generate a client secret ID when a new client is created" do
          model.client_type = "public"
          expect { model.save! }.not_to change(model, :client_secret_id).from(nil)
        end
      end
    end

    describe "#generate_public_id" do
      it "generates a public ID when a new client is created" do
        expect { model.save! }.to change(model, :public_id).from(nil).to(be_present)
      end
    end
  end

  describe "#client_secret" do
    context "when client type is confidential" do
      it "returns a deterministic HMAC-based secret" do
        model.save!
        secret1 = model.client_secret
        secret2 = model.client_secret

        aggregate_failures do
          expect(secret1).to be_present
          expect(secret1).to eq(secret2)
          expect(secret1).to be_a(String)
          expect(secret1.length).to eq(64) # SHA256 hex digest length
        end
      end
    end

    context "when client type is public" do
      it "returns nil" do
        model.client_type = "public"
        model.save!
        expect(model.client_secret).to be_nil
      end
    end
  end

  describe "#authenticate_with_secret" do
    context "when client type is confidential" do
      before { model.save! }

      it "returns true for correct secret" do
        correct_secret = model.client_secret
        expect(model.authenticate_with_secret(correct_secret)).to be true
      end

      it "returns false for incorrect secret" do
        expect(model.authenticate_with_secret("wrong_secret")).to be false
      end

      it "returns false for nil secret" do
        expect(model.authenticate_with_secret(nil)).to be false
      end

      it "returns false for empty secret" do
        expect(model.authenticate_with_secret("")).to be false
      end
    end

    context "when client type is public" do
      it "returns false for any secret" do
        model.client_type = "public"
        model.save!
        expect(model.authenticate_with_secret("any_secret")).to be false
      end
    end
  end

  describe "#new_authorization_grant" do
    subject(:call_method) { model.new_authorization_grant(user:, challenge_params:) }

    let(:user) { create(:user) }
    let(:challenge_params) { attributes_for(:token_authority_challenge) }

    it "returns a TokenAuthority::AuthorizationGrant with appropriate values" do
      object = call_method
      aggregate_failures do
        expect(object).to be_a(TokenAuthority::AuthorizationGrant)
        expect(object.token_authority_client).to eq(model)
        expect(object.user).to eq(user)
        expect(object.token_authority_challenge.code_challenge).to eq(challenge_params[:code_challenge])
        expect(object.token_authority_challenge.code_challenge_method).to eq(challenge_params[:code_challenge_method])
        expect(object.token_authority_challenge.redirect_uri).to eq(challenge_params[:redirect_uri])
      end
    end
  end

  describe "#new_authorization_request" do
    subject(:call_method) { model.new_authorization_request(**request_attrs.except(:token_authority_client)) }

    let(:user) { create(:user) }
    let(:request_attrs) { attributes_for(:token_authority_authorization_request, client_id: model.id, token_authority_client: model) }

    it "returns a TokenAuthority::AuthorizationRequest with appropriate values" do
      object = call_method
      aggregate_failures do
        expect(object).to be_a(TokenAuthority::AuthorizationRequest)
        expect(object.client_id).to eq(model.id)
        expect(object.code_challenge).to eq(request_attrs[:code_challenge])
        expect(object.code_challenge_method).to eq(request_attrs[:code_challenge_method])
        expect(object.redirect_uri).to eq(request_attrs[:redirect_uri])
        expect(object.response_type).to eq(request_attrs[:response_type])
        expect(object.state).to eq(request_attrs[:state])
      end
    end
  end

  describe "#url_for_redirect" do
    context "with valid params" do
      let(:params) { {foo: "bar"} }

      it "returns the redirect_uri with the params" do
        expect(model.url_for_redirect(params:)).to eq("http://localhost:3000/?foo=bar")
      end
    end

    context "with invalid params" do
      let(:params) { "foobar" }

      it "raises a TokenAuthority::InvalidRedirectUrlError" do
        expect { model.url_for_redirect(params:) }.to raise_error(TokenAuthority::InvalidRedirectUrlError)
      end
    end
  end

  describe "#url_based?" do
    it "returns false" do
      expect(model.url_based?).to be false
    end
  end
end
