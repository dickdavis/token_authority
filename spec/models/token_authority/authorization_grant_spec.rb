# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationGrant, type: :model do
  subject(:model) { build(:token_authority_authorization_grant) }

  describe "associations" do
    specify(:aggregate_failures) do
      expect(model).to belong_to(:user)
      expect(model).to belong_to(:token_authority_client)
      expect(model).to have_many(:token_authority_sessions)
      expect(model).to have_one(:token_authority_challenge).optional
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
    end

    context "when the token authority client has a confidential client type" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      it_behaves_like "a model that creates TokenAuthority sessions"
      it_behaves_like "updates the redeemed attribute"
    end
  end
end
