# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AuthorizationsController, type: :request do
  shared_examples "handles an invalid request" do
    it "redirects to the client redirect uri with the `invalid_request` error and state params" do
      call_endpoint
      redirect_params = Rack::Utils.parse_query(URI.parse(response.location).query)
      aggregate_failures do
        expect(response.location).to match(token_authority_client.primary_redirect_uri)
        expect(redirect_params["error"]).to eq("invalid_request")
        expect(redirect_params["state"]).to eq(state)
      end
    end
  end

  shared_examples "redirects successful authorize request" do
    it "redirects the user to the authorization grant page and stores state in session" do
      call_endpoint
      aggregate_failures do
        expect(response).to redirect_to(token_authority.new_authorization_grant_path)
        expect(session[:token_authority_internal_state]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
      end
    end
  end

  shared_examples "handles an invalid_target error" do
    it "redirects to the client redirect uri with the `invalid_target` error and state params" do
      call_endpoint
      redirect_params = Rack::Utils.parse_query(URI.parse(response.location).query)
      aggregate_failures do
        expect(response.location).to match(token_authority_client.primary_redirect_uri)
        expect(redirect_params["error"]).to eq("invalid_target")
        expect(redirect_params["state"]).to eq(state)
      end
    end
  end

  describe "GET /authorize" do
    subject(:call_endpoint) { get token_authority.authorize_path, params: }

    let(:params) do
      {client_id:, state:, code_challenge:, code_challenge_method:, redirect_uri:, response_type:, resource:}.compact
    end
    let(:resource) { nil }
    let(:client_id) { token_authority_client.public_id }
    let(:state) { "foobar" }
    let(:code_challenge) { "code_challenge" }
    let(:code_challenge_method) { "S256" }
    let(:redirect_uri) { token_authority_client.primary_redirect_uri }
    let(:response_type) { "code" }

    context "when the client type is public" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }

      context "when the client_id param is missing" do
        let(:client_id) { nil }

        it "responds with HTTP status unauthorized" do
          call_endpoint
          expect(response).to have_http_status(:unauthorized)
        end
      end

      context "when an invalid code_challenge param is provided" do
        let(:code_challenge) { nil }

        it_behaves_like "handles an invalid request"
      end

      context "when an invalid code_challenge_method param is provided" do
        let(:code_challenge_method) { nil }

        it_behaves_like "handles an invalid request"
      end

      context "when an invalid redirect_uri param is provided" do
        let(:redirect_uri) { nil }

        it "responds with HTTP status bad request" do
          call_endpoint
          expect(response).to have_http_status(:bad_request)
        end
      end

      context "when an invalid response_type param is provided" do
        let(:response_type) { nil }

        it_behaves_like "handles an invalid request"
      end

      context "when authorization request is valid" do
        it_behaves_like "redirects successful authorize request"
      end

      context "when the redirect URL is malformed" do
        before do
          allow_any_instance_of(TokenAuthority::Client).to receive(:url_for_redirect).and_raise(TokenAuthority::InvalidRedirectUrlError)
        end

        let(:response_type) { "invalid" }

        it "responds with HTTP status bad request" do
          call_endpoint
          expect(response).to have_http_status(:bad_request)
        end
      end

      context "with RFC 8707 resource indicators" do
        let(:configured_resources) do
          {
            "https://api.example.com" => "Main API",
            "https://api1.example.com" => "API 1",
            "https://api2.example.com" => "API 2"
          }
        end

        before do
          allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(configured_resources)
        end

        context "when a valid resource URI is provided" do
          let(:resource) { "https://api.example.com" }

          it_behaves_like "redirects successful authorize request"

          it "stores the resource in the internal state" do
            call_endpoint
            internal_state = session[:token_authority_internal_state]
            decoded = TokenAuthority::JsonWebToken.decode(internal_state)
            expect(decoded[:resources]).to eq([resource])
          end
        end

        context "when multiple valid resource URIs are provided" do
          let(:resource) { ["https://api1.example.com", "https://api2.example.com"] }

          it_behaves_like "redirects successful authorize request"

          it "stores all resources in the internal state" do
            call_endpoint
            internal_state = session[:token_authority_internal_state]
            decoded = TokenAuthority::JsonWebToken.decode(internal_state)
            expect(decoded[:resources]).to match_array(resource)
          end
        end

        context "when an invalid resource URI is provided" do
          let(:resource) { "not-a-valid-uri" }

          it_behaves_like "handles an invalid_target error"
        end

        context "when a resource URI with fragment is provided" do
          let(:resource) { "https://api.example.com#fragment" }

          it_behaves_like "handles an invalid_target error"
        end

        context "when resource is required but not provided" do
          before do
            allow(TokenAuthority.config).to receive(:rfc_8707_require_resource).and_return(true)
          end

          it_behaves_like "handles an invalid_target error"
        end

        context "when resource is not in the configured resources" do
          let(:resource) { "https://not-configured.example.com" }

          it_behaves_like "handles an invalid_target error"
        end

        context "when RFC 8707 is disabled (no resources configured)" do
          before do
            allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(nil)
          end

          context "when no resource is provided" do
            let(:resource) { nil }

            it_behaves_like "redirects successful authorize request"
          end

          context "when a resource is provided" do
            let(:resource) { "https://api.example.com" }

            it_behaves_like "handles an invalid_target error"
          end
        end
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      include_context "with an authenticated client", :get, :token_authority_authorize_path

      it_behaves_like "an endpoint that requires client authentication"

      context "when the client_id param is missing" do
        let(:client_id) { nil }

        it "does not respond with HTTP status unauthorized" do
          call_endpoint
          expect(response).not_to have_http_status(:unauthorized)
        end
      end

      context "when an invalid code_challenge param is provided" do
        let(:code_challenge) { nil }

        it_behaves_like "handles an invalid request"
      end

      context "when an invalid code_challenge_method param is provided" do
        let(:code_challenge_method) { nil }

        it_behaves_like "handles an invalid request"
      end

      context "when an invalid redirect_uri param is provided" do
        let(:redirect_uri) { "invalid" }

        it "responds with HTTP status bad request" do
          call_endpoint
          expect(response).to have_http_status(:bad_request)
        end
      end

      context "when an invalid response_type param is provided" do
        let(:response_type) { nil }

        it_behaves_like "handles an invalid request"
      end

      context "when authorization request is valid" do
        it_behaves_like "redirects successful authorize request"
      end

      context "when no redirect_uri param is provided" do
        let(:redirect_uri) { nil }

        it_behaves_like "redirects successful authorize request"
      end

      context "when no PKCE params are provided" do
        let(:code_challenge) { nil }
        let(:code_challenge_method) { nil }

        it_behaves_like "redirects successful authorize request"
      end

      context "when the redirect URL is malformed" do
        before do
          allow_any_instance_of(TokenAuthority::Client).to receive(:url_for_redirect).and_raise(TokenAuthority::InvalidRedirectUrlError)
        end

        let(:response_type) { "invalid" }

        it "responds with HTTP status bad request" do
          call_endpoint
          expect(response).to have_http_status(:bad_request)
        end
      end
    end
  end

  private

  def token_authority_authorize_path
    token_authority.authorize_path
  end
end
