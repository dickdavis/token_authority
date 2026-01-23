# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationGrantsController, type: :request do
  # Helper to set up session state via the authorize endpoint
  def start_authorization_flow(client, state: "foobar", resources: [], scope: nil)
    params = {
      client_id: client.public_id,
      state:,
      code_challenge: "code_challenge",
      code_challenge_method: "S256",
      redirect_uri: client.primary_redirect_uri,
      response_type: "code"
    }

    # Add resource parameters if provided
    params[:resource] = resources if resources.any?

    # Add scope parameter if provided
    params[:scope] = scope if scope.present?

    # Confidential clients require HTTP Basic auth
    if client.confidential_client_type?
      auth = ActionController::HttpAuthentication::Basic.encode_credentials(client.public_id, client.client_secret)
      get token_authority.authorize_path, params:, headers: {"HTTP_AUTHORIZATION" => auth}
    else
      get token_authority.authorize_path, params:
    end
  end

  describe "GET /new" do
    subject(:call_endpoint) do
      get token_authority.new_authorization_grant_path
    end

    let_it_be(:user) { create(:user) }

    before do
      sign_in(user)
    end

    context "when the client type is public" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      before { start_authorization_flow(token_authority_client) }

      it "renders a successful response" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      before { start_authorization_flow(token_authority_client) }

      it "renders a successful response" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end

    context "when session state is missing" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      # Don't call start_authorization_flow, so session state is never set

      it "returns bad request with error message" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.body).to include("Authorization state not found")
        end
      end
    end

    context "when session state is invalid" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      before do
        start_authorization_flow(token_authority_client)
        # Stub to simulate invalid/expired JWT
        allow(TokenAuthority::AuthorizationRequest).to receive(:from_internal_state_token)
          .and_raise(JWT::DecodeError)
      end

      it "returns bad request with error message" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.body).to include("Invalid or expired authorization state")
        end
      end
    end

    context "with RFC 8707 resource indicators" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:resources) { ["https://api.example.com", "https://billing.example.com"] }
      let(:configured_resources) do
        {
          "https://api.example.com" => "https://api.example.com",
          "https://billing.example.com" => "https://billing.example.com"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(configured_resources)
        start_authorization_flow(token_authority_client, resources:)
      end

      it "displays resource URIs on the consent screen" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:ok)
          expect(response.body).to include("https://api.example.com")
          expect(response.body).to include("https://billing.example.com")
        end
      end

      context "when resource display names are configured" do
        let(:configured_resources) do
          {
            "https://api.example.com" => "Main API",
            "https://billing.example.com" => "Billing Service"
          }
        end

        it "displays human-friendly names instead of URIs" do
          call_endpoint
          aggregate_failures do
            expect(response).to have_http_status(:ok)
            expect(response.body).to include("Main API")
            expect(response.body).to include("Billing Service")
            expect(response.body).not_to include("https://api.example.com")
            expect(response.body).not_to include("https://billing.example.com")
          end
        end
      end

      context "when no resources are requested" do
        let(:resources) { [] }

        it "does not display the resources section" do
          call_endpoint
          aggregate_failures do
            expect(response).to have_http_status(:ok)
            expect(response.body).not_to include("requesting access to")
          end
        end
      end
    end

    context "with scopes" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:scope) { "read write" }
      let(:configured_scopes) do
        {
          "read" => "Read access",
          "write" => "Write access"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return(configured_scopes)
        start_authorization_flow(token_authority_client, scope:)
      end

      it "renders successfully" do
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
          expect(response).to redirect_to("http://localhost:3000/?code=#{TokenAuthority::AuthorizationGrant.last.public_id}&state=#{client_state}")
        end
      end

      it "clears the session state after redirect" do
        call_endpoint
        expect(session[:token_authority_internal_state]).to be_nil
      end
    end

    context "when the authorization grant fails to create" do
      before do
        allow_any_instance_of(TokenAuthority::AuthorizationGrant).to receive(:save).and_return(false)
      end

      it "redirects to client redirection_uri with state and error params" do
        call_endpoint
        expect(response).to redirect_to("http://localhost:3000/?error=invalid_request&state=#{client_state}")
      end

      it "clears the session state after redirect" do
        call_endpoint
        expect(session[:token_authority_internal_state]).to be_nil
      end
    end
  end

  shared_examples "handles user authorization rejection" do
    let(:approve) { "false" }

    it "redirects to client redirection_uri with state and error params" do
      call_endpoint
      expect(response).to redirect_to("http://localhost:3000/?error=access_denied&state=#{client_state}")
    end

    it "clears the session state after redirect" do
      call_endpoint
      expect(session[:token_authority_internal_state]).to be_nil
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

    it "clears the session state on error" do
      call_endpoint
      expect(session[:token_authority_internal_state]).to be_nil
    end
  end

  describe "POST /create" do
    subject(:call_endpoint) { post token_authority.authorization_grants_path, params: {approve:} }

    let_it_be(:user) { create(:user) }

    let(:approve) { "true" }
    let(:client_state) { "foobar" }

    before do
      sign_in(user)
      start_authorization_flow(token_authority_client, state: client_state)
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

    context "with scopes" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:scope) { "read write delete" }
      let(:configured_scopes) do
        {
          "read" => "Read access",
          "write" => "Write access",
          "delete" => "Delete access"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return(configured_scopes)
        start_authorization_flow(token_authority_client, state: client_state, scope:)
      end

      it "stores the scopes on the authorization grant" do
        expect { call_endpoint }.to change(TokenAuthority::AuthorizationGrant, :count).by(1)
        expect(TokenAuthority::AuthorizationGrant.last.scopes).to eq(["read", "write", "delete"])
      end
    end
  end
end
