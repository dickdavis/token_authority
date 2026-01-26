# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Api::V1::Users", type: :request do
  describe "GET /api/v1/users/current" do
    let_it_be(:user) { create(:user) }
    let_it_be(:token_authority_client) { create(:token_authority_client) }
    let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
    let(:scope) { "read" }
    let(:access_token) { build(:token_authority_access_token, token_authority_session:, scope:) }
    let(:encoded_token) { access_token.to_encoded_token }
    let(:headers) { {"AUTHORIZATION" => "Bearer #{encoded_token}"} }

    subject(:call_endpoint) { get "/api/v1/users/current", headers: }

    context "with a valid access token with read scope" do
      it "returns the current user data" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:ok)
          expect(response.parsed_body).to eq({"id" => user.id, "email" => user.email})
        end
      end

      it "emits token authentication succeeded event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.succeeded")
      end
    end

    context "with a valid access token without read scope" do
      let(:scope) { "write" }

      it "returns forbidden with insufficient_scope error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:forbidden)
          expect(response.parsed_body).to eq({"error" => "insufficient_scope", "required" => "read", "granted" => ["write"]})
        end
      end
    end

    context "with a valid access token with no scope" do
      let(:scope) { nil }

      it "returns forbidden with insufficient_scope error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:forbidden)
          expect(response.parsed_body).to eq({"error" => "insufficient_scope", "required" => "read", "granted" => []})
        end
      end
    end

    context "without an Authorization header" do
      let(:headers) { {} }

      it "returns unauthorized with missing_auth_header error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.missing_auth_header")})
        end
      end

      it "includes WWW-Authenticate header with resource_metadata and scope" do
        call_endpoint
        # Derives from dummy app's resource config (http://localhost:3000/api/)
        # Includes scopes_supported from the resource config
        expect(response.headers["WWW-Authenticate"]).to eq(
          'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource", scope="read write delete profile"'
        )
      end

      context "when no resources are configured" do
        around do |example|
          original_resources = TokenAuthority.config.resources.dup
          TokenAuthority.config.resources = {}
          example.run
          TokenAuthority.config.resources = original_resources
        end

        it "falls back to request host for metadata URL" do
          call_endpoint
          expect(response.headers["WWW-Authenticate"]).to eq(
            'Bearer resource_metadata="http://www.example.com/.well-known/oauth-protected-resource"'
          )
        end
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "missing_authorization_header")
      end
    end

    context "with a blank Authorization header" do
      let(:headers) { {"AUTHORIZATION" => ""} }

      it "returns unauthorized with missing_auth_header error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.missing_auth_header")})
        end
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "missing_authorization_header")
      end
    end

    context "with a malformed token" do
      let(:headers) { {"AUTHORIZATION" => "Bearer not.a.valid.token"} }

      it "returns unauthorized with invalid_token error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.invalid_token")})
        end
      end

      it "includes WWW-Authenticate header with scope and error parameters" do
        call_endpoint
        expect(response.headers["WWW-Authenticate"]).to eq(
          'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource", scope="read write delete profile", error="invalid_token"'
        )
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "invalid_token_format")
      end
    end

    context "with an expired token" do
      let(:access_token) { build(:token_authority_access_token, token_authority_session:, exp: 1.minute.ago.to_i) }

      it "returns unauthorized with unauthorized_token error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.unauthorized_token")})
        end
      end

      it "includes WWW-Authenticate header with scope and error parameters" do
        call_endpoint
        expect(response.headers["WWW-Authenticate"]).to eq(
          'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource", scope="read write delete profile", error="invalid_token"'
        )
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "unauthorized_token")
      end
    end

    context "with a revoked session" do
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "revoked") }

      it "returns unauthorized with unauthorized_token error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.unauthorized_token")})
        end
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "unauthorized_token")
      end
    end

    context "with a refreshed session" do
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed") }

      it "returns unauthorized with unauthorized_token error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.unauthorized_token")})
        end
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "unauthorized_token")
      end
    end

    context "when session does not exist for the token" do
      before do
        token_authority_session.destroy
      end

      it "returns unauthorized with unauthorized_token error" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:unauthorized)
          expect(response.parsed_body).to eq({"error" => I18n.t("token_authority.errors.unauthorized_token")})
        end
      end

      it "emits token authentication failed event" do
        expect { call_endpoint }
          .to emit_event("token_authority.authentication.token.failed")
          .with_payload(failure_reason: "unauthorized_token")
      end
    end
  end
end
