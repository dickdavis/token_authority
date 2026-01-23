# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationGrant, type: :model do
  subject(:model) { build(:token_authority_authorization_grant) }

  describe "associations" do
    specify(:aggregate_failures) do
      expect(model).to belong_to(:user)
      expect(model).to belong_to(:token_authority_client).optional
      expect(model).to have_many(:token_authority_sessions)
      expect(model).to have_one(:token_authority_challenge).optional
    end
  end

  describe "validations" do
    describe "must_have_client_identifier" do
      context "when token_authority_client is present" do
        it "is valid" do
          grant = build(:token_authority_authorization_grant, token_authority_client: create(:token_authority_client))
          expect(grant).to be_valid
        end
      end

      context "when client_id_url is present" do
        it "is valid" do
          grant = build(:token_authority_authorization_grant, token_authority_client: nil, client_id_url: "https://example.com/oauth-client")
          expect(grant).to be_valid
        end
      end

      context "when neither token_authority_client nor client_id_url is present" do
        it "is invalid" do
          grant = build(:token_authority_authorization_grant, token_authority_client: nil, client_id_url: nil)

          aggregate_failures do
            expect(grant).not_to be_valid
            expect(grant.errors[:base]).to include(I18n.t("activerecord.errors.models.token_authority/authorization_grant.attributes.base.must_have_client_identifier"))
          end
        end
      end
    end
  end

  describe "#resolved_client" do
    context "when token_authority_client is present" do
      let(:client) { create(:token_authority_client) }
      let(:grant) { create(:token_authority_authorization_grant, token_authority_client: client) }

      it "returns the token_authority_client" do
        expect(grant.resolved_client).to eq(client)
      end
    end

    context "when client_id_url is present" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:grant) { create(:token_authority_authorization_grant, token_authority_client: nil, client_id_url: client_id_url) }

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it "returns a ClientMetadataDocument" do
        result = grant.resolved_client

        aggregate_failures do
          expect(result).to be_a(TokenAuthority::ClientMetadataDocument)
          expect(result.public_id).to eq(client_id_url)
        end
      end

      it "memoizes the result" do
        grant.resolved_client
        grant.resolved_client

        expect(TokenAuthority::ClientIdResolver).to have_received(:resolve).once
      end
    end

    context "when neither is present" do
      let(:grant) { build(:token_authority_authorization_grant, token_authority_client: nil, client_id_url: nil) }

      it "returns nil" do
        expect(grant.resolved_client).to be_nil
      end
    end
  end

  describe "#active_token_authority_session" do
    subject(:method_call) { token_authority_authorization_grant.active_token_authority_session }

    let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant) }

    context "when the authorization grant has an active token authority session" do
      it "returns the active token authority session for the authorization grant" do
        _first_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed")
        _second_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed")
        third_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:)

        expect(method_call).to eq(third_token_authority_session)
      end
    end

    context "when the authorization grant does not have an active token authority session" do
      before do
        create_list(:token_authority_session, 3, token_authority_authorization_grant:, status: "refreshed")
      end

      it "returns nil" do
        expect(method_call).to be_nil
      end
    end
  end

  shared_examples "updates the redeemed attribute" do
    it "updates the redeemed attribute and creates a TokenAuthority session" do
      expect { method_call }.to change(token_authority_authorization_grant, :redeemed).from(false).to(true)
        .and change(TokenAuthority::Session, :count).by(1)
    end
  end

  describe "#redeem" do
    subject(:method_call) { token_authority_authorization_grant.redeem }

    let(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, token_authority_client:) }
    let!(:token_authority_challenge) { create(:token_authority_challenge, token_authority_authorization_grant:) }

    context "when the token authority client has a public client type" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      it_behaves_like "a model that creates TokenAuthority sessions"
      it_behaves_like "updates the redeemed attribute"

      describe "RFC 8707 resource indicators" do
        let(:method_call_with_resources) { token_authority_authorization_grant.redeem(resources:) }

        it_behaves_like "a model that creates TokenAuthority sessions with RFC 8707 resources"
      end
    end

    context "when the token authority client has a confidential client type" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      it_behaves_like "a model that creates TokenAuthority sessions"
      it_behaves_like "updates the redeemed attribute"

      describe "RFC 8707 resource indicators" do
        let(:method_call_with_resources) { token_authority_authorization_grant.redeem(resources:) }

        it_behaves_like "a model that creates TokenAuthority sessions with RFC 8707 resources"
      end
    end

    context "when using a URL-based client" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:token_authority_authorization_grant) do
        create(:token_authority_authorization_grant, token_authority_client: nil, client_id_url: client_id_url)
      end
      let!(:token_authority_challenge) { create(:token_authority_challenge, token_authority_authorization_grant:) }

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it_behaves_like "a model that creates TokenAuthority sessions"
      it_behaves_like "updates the redeemed attribute"

      describe "RFC 8707 resource indicators" do
        let(:method_call_with_resources) { token_authority_authorization_grant.redeem(resources:) }

        it_behaves_like "a model that creates TokenAuthority sessions with RFC 8707 resources"
      end
    end
  end
end
