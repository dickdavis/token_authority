# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientsController, type: :request do
  describe "POST /register" do
    subject(:call_endpoint) { post token_authority.register_path, params: params, as: :json }

    let(:params) do
      {
        redirect_uris: ["https://example.com/callback"],
        client_name: "Test Client"
      }
    end

    context "when dynamic registration is disabled" do
      before do
        TokenAuthority.config.rfc_7591_enabled = false
      end

      it "returns 404" do
        call_endpoint
        expect(response).to have_http_status(:not_found)
      end
    end

    context "when dynamic registration is enabled" do
      before do
        TokenAuthority.config.rfc_7591_enabled = true
      end

      after do
        TokenAuthority.config.rfc_7591_enabled = false
      end

      it "creates a new client and returns 201" do
        expect { call_endpoint }.to change(TokenAuthority::Client, :count).by(1)
        expect(response).to have_http_status(:created)
      end

      it "returns the client_id and client_secret" do
        call_endpoint
        body = response.parsed_body

        aggregate_failures do
          expect(body["client_id"]).to be_present
          expect(body["client_secret"]).to be_present
          expect(body["client_id_issued_at"]).to be_present
          expect(body["redirect_uris"]).to eq(["https://example.com/callback"])
          expect(body["client_name"]).to eq("Test Client")
        end
      end

      it "marks the client as dynamically registered" do
        call_endpoint
        client = TokenAuthority::Client.last
        expect(client.dynamically_registered).to be true
      end

      context "with public client (token_endpoint_auth_method: none)" do
        let(:params) do
          {
            redirect_uris: ["https://example.com/callback"],
            client_name: "Public Client",
            token_endpoint_auth_method: "none"
          }
        end

        it "creates a public client without client_secret" do
          call_endpoint
          body = response.parsed_body

          aggregate_failures do
            expect(body["client_id"]).to be_present
            expect(body).not_to have_key("client_secret")
            expect(body["token_endpoint_auth_method"]).to eq("none")
          end
        end
      end

      context "with invalid redirect_uris" do
        let(:params) do
          {
            redirect_uris: ["not-a-valid-uri"],
            client_name: "Test Client"
          }
        end

        it "returns 400 with error" do
          call_endpoint

          aggregate_failures do
            expect(response).to have_http_status(:bad_request)
            expect(response.parsed_body["error"]).to eq("invalid_client_metadata")
          end
        end
      end

      context "with missing redirect_uris" do
        let(:params) do
          {
            client_name: "Test Client"
          }
        end

        it "returns 400 with error" do
          call_endpoint

          aggregate_failures do
            expect(response).to have_http_status(:bad_request)
            expect(response.parsed_body["error"]).to eq("invalid_client_metadata")
          end
        end
      end

      context "when initial access token is required" do
        before do
          TokenAuthority.config.rfc_7591_require_initial_access_token = true
          TokenAuthority.config.rfc_7591_initial_access_token_validator = ->(token) { token == "valid-token" }
        end

        after do
          TokenAuthority.config.rfc_7591_require_initial_access_token = false
          TokenAuthority.config.rfc_7591_initial_access_token_validator = nil
        end

        context "with valid token" do
          subject(:call_endpoint) do
            post token_authority.register_path,
              params: params,
              headers: {"Authorization" => "Bearer valid-token"},
              as: :json
          end

          it "creates the client" do
            expect { call_endpoint }.to change(TokenAuthority::Client, :count).by(1)
            expect(response).to have_http_status(:created)
          end
        end

        context "with invalid token" do
          subject(:call_endpoint) do
            post token_authority.register_path,
              params: params,
              headers: {"Authorization" => "Bearer invalid-token"},
              as: :json
          end

          it "returns 401" do
            call_endpoint

            aggregate_failures do
              expect(response).to have_http_status(:unauthorized)
              expect(response.parsed_body["error"]).to eq("invalid_token")
            end
          end
        end

        context "without token" do
          it "returns 401" do
            call_endpoint

            aggregate_failures do
              expect(response).to have_http_status(:unauthorized)
              expect(response.parsed_body["error"]).to eq("invalid_token")
            end
          end
        end
      end
    end
  end
end
