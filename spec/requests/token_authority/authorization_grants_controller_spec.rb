# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationGrantsController, type: :request do
  describe "GET /new" do
    subject(:call_endpoint) { get token_authority.new_authorization_grant_path, params: {state:} }

    let_it_be(:user) { create(:user) }

    let(:state) { authorization_request.to_internal_state_token }
    let(:authorization_request) { build(:token_authority_authorization_request, token_authority_client:, client_id: token_authority_client.id) }

    before do
      sign_in(user)
    end

    context "when the client type is public" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      it "renders a successful response" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      it "renders a successful response" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end
  end

  shared_examples "handles user authorization approval" do
    context "when the authorization grant is successfully created" do
      it "creates an authorization grant and redirects to client redirection_uri with state and code params" do
        aggregate_failures do
          expect { call_endpoint }.to change(TokenAuthority::AuthorizationGrant, :count)
          expect(response).to redirect_to("http://localhost:3000/?code=#{TokenAuthority::AuthorizationGrant.last.public_id}&state=#{authorization_request.state}")
        end
      end
    end

    context "when the authorization grant fails to create" do
      before do
        allow_any_instance_of(TokenAuthority::AuthorizationGrant).to receive(:save).and_return(false)
      end

      it "redirects to client redirection_uri with state and error params" do
        call_endpoint
        expect(response).to redirect_to("http://localhost:3000/?error=invalid_request&state=#{authorization_request.state}")
      end
    end
  end

  shared_examples "handles user authorization rejection" do
    let(:approve) { "false" }

    it "redirects to client redirection_uri with state and error params" do
      call_endpoint
      expect(response).to redirect_to("http://localhost:3000/?error=access_denied&state=#{authorization_request.state}")
    end
  end

  shared_examples "handles malformed redirect URL" do
    before do
      allow_any_instance_of(TokenAuthority::Client).to receive(:url_for_redirect).and_raise(TokenAuthority::InvalidRedirectUrlError)
    end

    it "responds with HTTP status bad request" do
      call_endpoint
      expect(response).to have_http_status(:bad_request)
    end
  end

  describe "POST /create" do
    subject(:call_endpoint) { post token_authority.authorization_grants_path, params: {state:, approve:} }

    let_it_be(:user) { create(:user) }

    let(:approve) { "true" }
    let(:state) { authorization_request.to_internal_state_token }
    let(:authorization_request) { build(:token_authority_authorization_request, token_authority_client:, client_id: token_authority_client.id) }

    before do
      sign_in(user)
    end

    context "when the client type is public" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      it_behaves_like "handles user authorization approval"
      it_behaves_like "handles user authorization rejection"
      it_behaves_like "handles malformed redirect URL"
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      it_behaves_like "handles user authorization approval"
      it_behaves_like "handles user authorization rejection"
      it_behaves_like "handles malformed redirect URL"
    end
  end
end
