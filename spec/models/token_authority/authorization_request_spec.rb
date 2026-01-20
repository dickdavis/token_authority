# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationRequest, type: :model do
  subject(:model) { described_class.new(**attrs) }

  let(:attrs) do
    {
      token_authority_client:,
      client_id:,
      code_challenge:,
      code_challenge_method:,
      redirect_uri:,
      response_type:,
      state:

    }
  end

  let(:client_id) { initial_attrs[:client_id] }
  let(:code_challenge) { initial_attrs[:code_challenge] }
  let(:code_challenge_method) { initial_attrs[:code_challenge_method] }
  let(:redirect_uri) { initial_attrs[:redirect_uri] }
  let(:response_type) { initial_attrs[:response_type] }
  let(:state) { initial_attrs[:state] }

  describe "validations" do
    let_it_be(:initial_attrs) { attributes_for(:token_authority_authorization_request) }

    shared_examples "validates response_type param" do
      it "must be present and code" do
        aggregate_failures do
          expect(model).not_to allow_value(nil).for(:response_type)
          expect(model).to allow_value("code").for(:response_type)
          expect(model).not_to allow_value("invalid-response-type").for(:response_type)
        end
      end
    end

    shared_examples "validates client_id param" do
      it "validates client_id is present and maps to a valid client" do
        aggregate_failures do
          expect(model).to allow_value(client_id).for(:client_id)
          expect(model).not_to allow_value(nil).for(:client_id)
          expect(model).not_to allow_value("invalid-client-id").for(:client_id)
        end
      end
    end

    shared_examples "does not require client_id param" do
      it "does not require client_id param" do
        expect(model).to allow_value(nil).for(:client_id)
      end
    end

    shared_examples "validates client_id param maps to a valid client if present" do
      it "does not allow invalid client_id" do
        aggregate_failures do
          expect(model).to allow_value(client_id).for(:client_id)
          expect(model).not_to allow_value("invalid-client-id").for(:client_id)
        end
      end
    end

    shared_examples "validates PKCE params" do
      context "with no code_challenge" do
        let(:code_challenge) { nil }

        it "requires a code_challenge" do
          expect(model).not_to be_valid
        end
      end

      context "with no code_challenge_method" do
        let(:code_challenge_method) { nil }

        it "requires a code_challenge_method" do
          expect(model).not_to be_valid
        end
      end

      context "with a code_challenge_method" do
        it "requires a valid code_challenge_method" do
          aggregate_failures do
            expect(model).to allow_value("S256").for(:code_challenge_method)
            expect(model).not_to allow_value("invalid").for(:code_challenge_method)
          end
        end
      end
    end

    shared_examples "does not validate PKCE params" do
      let(:code_challenge) { nil }
      let(:code_challenge_method) { nil }

      it "does not require code_challenge and code_challenge_method" do
        expect(model).to be_valid
      end
    end

    shared_examples "validates redirect_uri param" do
      it "validates redirect_uri param" do
        aggregate_failures do
          expect(model).to allow_value(token_authority_client.redirect_uri).for(:redirect_uri)
          expect(model).not_to allow_value(nil).for(:redirect_uri)
          expect(model).not_to allow_value("invalid-redirect-uri").for(:redirect_uri)
        end
      end
    end

    shared_examples "does not validate redirect_uri param" do
      it "does not require redirect_uri param" do
        expect(model).to allow_value(nil).for(:redirect_uri)
      end
    end

    context "when no TokenAuthority client is provided" do
      let(:token_authority_client) { nil }

      it "adds a token_authority_client error to the model and skips other validations" do
        aggregate_failures do
          expect(model).not_to be_valid
          expect(model.errors.count).to eq(1)
          expect(model.errors.first.attribute).to eq(:token_authority_client)
          expect(model.errors.first.type).to eq(:invalid)
        end
      end
    end

    context "when TokenAuthority client is public" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:client_id) { token_authority_client.public_id }

      it_behaves_like "validates response_type param"
      it_behaves_like "validates client_id param"
      it_behaves_like "validates PKCE params"
      it_behaves_like "validates redirect_uri param"
    end

    context "when TokenAuthority client is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      let(:client_id) { token_authority_client.public_id }

      it_behaves_like "validates response_type param"
      it_behaves_like "validates client_id param maps to a valid client if present"
      it_behaves_like "does not validate PKCE params"
      it_behaves_like "does not validate redirect_uri param"

      context "when a client_id param is not provided" do
        let(:client_id) { nil }

        it_behaves_like "does not require client_id param"
      end

      context "when a PKCE param is provided" do
        let(:code_challenge) { "code_challenge" }
        let(:code_challenge_method) { "S256" }

        it_behaves_like "validates PKCE params"
      end
    end
  end
end
