# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::SessionsController, type: :request do
  shared_examples "requires a valid code param" do
    context "when the authorization grant is not found" do
      let(:code) { "foobar" }

      it "responds with HTTP status bad request and error invalid_grant as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_grant"})
        end
      end
    end

    context "when the authorization grant has already been redeemed" do
      let(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, redeemed: true) }

      it "responds with HTTP status bad request and error invalid_grant as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_grant"})
        end
      end
    end
  end

  shared_examples "requires a valid client_id param" do
    let(:client_id) { nil }

    it "returns HTTP status unauthorized and access denied message" do
      call_endpoint
      aggregate_failures do
        expect(response).to have_http_status(:unauthorized)
        expect(response.body.chomp).to eq("HTTP Basic: Access denied.")
      end
    end
  end

  shared_examples "does not require a valid client_id param" do
    let(:client_id) { nil }

    it "does not return HTTP status unauthorized and access denied message" do
      call_endpoint
      aggregate_failures do
        expect(response).not_to have_http_status(:unauthorized)
        expect(response.body.chomp).not_to eq("HTTP Basic: Access denied.")
      end
    end
  end

  shared_examples "generates an OAuth session" do
    context "when all params are valid" do
      it "creates an OAuth session and serializes the token data" do
        Timecop.freeze(Time.zone.now) do
          aggregate_failures do
            expect { call_endpoint }.to change(TokenAuthority::Session, :count).by(1)
            expect(response).to have_http_status(:ok)
            body = response.parsed_body
            expect(body["access_token"]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
            expect(body["refresh_token"]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
            expect(body["token_type"]).to eq("bearer")
            expect(body["expires_in"]).to eq(5.minutes.from_now.to_i)
          end
        end
      end

      context "when oauth token creation raises the server error" do
        it "responds with HTTP status internal_server_error and error server_error as JSON" do
          allow_any_instance_of(TokenAuthority::AuthorizationGrant).to receive(:redeem).and_raise(TokenAuthority::ServerError, "foobar")
          allow_any_instance_of(TokenAuthority::Session).to receive(:refresh).and_raise(TokenAuthority::ServerError, "foobar")
          call_endpoint
          aggregate_failures do
            expect(response).to have_http_status(:internal_server_error)
            expect(response.parsed_body).to eq({"error" => "server_error"})
          end
        end
      end
    end
  end

  shared_examples "requires a valid redirect_uri param" do
    context "when the params do not include a redirect_uri" do
      let(:redirect_uri) { nil }

      it "does not respond with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end
    end

    context "when the params include an invalid redirect_uri" do
      let(:redirect_uri) { "https://invalid.com" }

      it "responds with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end
    end

    context "when the params include a valid redirect_uri" do
      let(:redirect_uri) { token_authority_client.primary_redirect_uri }

      it "does not respond with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).not_to have_http_status(:bad_request)
          expect(response.parsed_body).not_to eq({"error" => "invalid_request"})
        end
      end
    end
  end

  shared_examples "does not require a valid redirect_uri param" do
    context "when the params do not include a redirect_uri" do
      let(:redirect_uri) { nil }

      it "does not respond with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).not_to have_http_status(:bad_request)
          expect(response.parsed_body).not_to eq({"error" => "invalid_request"})
        end
      end
    end

    context "when the params include a redirect_uri" do
      let(:redirect_uri) { "https://example.com" }

      it "does not respond with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).not_to have_http_status(:bad_request)
          expect(response.parsed_body).not_to eq({"error" => "invalid_request"})
        end
      end
    end
  end

  shared_examples "requires PKCE" do
    let(:code_verifier) { nil }

    context "when code_verifier param is missing" do
      it "responds with HTTP status bad request and error invalid_grant as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end
    end
  end

  shared_examples "does not require PKCE" do
    context "when code verifier is not provided" do
      let(:code_verifier) { nil }

      it "creates an OAuth session and serializes the token data" do
        Timecop.freeze(Time.zone.now) do
          aggregate_failures do
            expect { call_endpoint }.to change(TokenAuthority::Session, :count).by(1)
            expect(response).to have_http_status(:ok)
            body = response.parsed_body
            expect(body["access_token"]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
            expect(body["refresh_token"]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
            expect(body["token_type"]).to eq("bearer")
            expect(body["expires_in"]).to eq(5.minutes.from_now.to_i)
          end
        end
      end
    end
  end

  shared_examples "implements PKCE" do
    context "when code_verifier is valid" do
      let(:code_verifier) { "code_verifier" }

      context "when all other params are valid" do
        it "creates an OAuth session and serializes the token data" do
          Timecop.freeze(Time.zone.now) do
            aggregate_failures do
              expect { call_endpoint }.to change(TokenAuthority::Session, :count).by(1)
              expect(response).to have_http_status(:ok)
              body = response.parsed_body
              expect(body["access_token"]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
              expect(body["refresh_token"]).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
              expect(body["token_type"]).to eq("bearer")
              expect(body["expires_in"]).to eq(5.minutes.from_now.to_i)
            end
          end
        end
      end
    end

    context "when code_verifier is invalid" do
      let(:code_verifier) { "foobar" }

      it "responds with HTTP status bad request and error invalid_grant as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end
    end
  end

  describe 'POST /token (grant_type="authorization_code")' do
    let_it_be(:user) { create(:user) }

    let(:params) { {client_id:, code:, code_verifier:, grant_type:, redirect_uri:}.compact }
    let(:grant_type) { "authorization_code" }
    let(:code) { token_authority_authorization_grant.public_id }

    context "when the client type is public" do
      subject(:call_endpoint) { post token_authority.create_session_path, params: }

      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

      let(:client_id) { token_authority_client.public_id }
      let(:code_verifier) { "code_verifier" }
      let(:redirect_uri) { token_authority_client.primary_redirect_uri }

      it_behaves_like "requires a valid code param"
      it_behaves_like "requires a valid client_id param"
      it_behaves_like "requires a valid redirect_uri param"
      it_behaves_like "generates an OAuth session"
      it_behaves_like "implements PKCE"
      it_behaves_like "requires PKCE"
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

      let(:client_id) { nil }
      let(:code_verifier) { nil }
      let(:redirect_uri) { nil }

      include_context "with an authenticated client", :post, :token_authority_create_session_path

      it_behaves_like "an endpoint that requires client authentication"
      it_behaves_like "requires a valid code param"

      context "when client did not use additional security challenges for authorize request" do
        before_all do
          token_authority_authorization_grant.token_authority_challenge.update!(
            code_challenge: nil,
            code_challenge_method: nil,
            redirect_uri: nil
          )
        end

        it_behaves_like "does not require a valid client_id param"
        it_behaves_like "does not require PKCE"
        it_behaves_like "generates an OAuth session"
      end

      context "when client provided a redirect_uri in authorize request" do
        before do
          token_authority_authorization_grant.reload.token_authority_challenge.update!(
            code_challenge: nil,
            code_challenge_method: nil,
            redirect_uri: token_authority_client.primary_redirect_uri
          )
        end

        context "when the params do not include a redirect_uri" do
          it "responds with HTTP status bad request and error invalid_request as JSON" do
            call_endpoint
            aggregate_failures do
              expect(response).to have_http_status(:bad_request)
              expect(response.parsed_body).to eq({"error" => "invalid_request"})
            end
          end
        end

        context "when the params include an invalid redirect_uri" do
          let(:redirect_uri) { "https://invalid.com" }

          it "responds with HTTP status bad request and error invalid_request as JSON" do
            call_endpoint
            aggregate_failures do
              expect(response).to have_http_status(:bad_request)
              expect(response.parsed_body).to eq({"error" => "invalid_request"})
            end
          end
        end

        context "when the params include a valid redirect_uri" do
          let(:redirect_uri) { token_authority_client.primary_redirect_uri }

          it_behaves_like "generates an OAuth session"

          it "does not respond with HTTP status bad request and error invalid_request as JSON" do
            call_endpoint
            aggregate_failures do
              expect(response).not_to have_http_status(:bad_request)
              expect(response.parsed_body).not_to eq({"error" => "invalid_request"})
            end
          end
        end
      end

      context "when client secured authorize request with PKCE" do
        before_all do
          token_authority_authorization_grant.token_authority_challenge.update!(
            redirect_uri: nil
          )
        end

        let(:code_verifier) { "code_verifier" }

        it_behaves_like "implements PKCE"
        it_behaves_like "generates an OAuth session"
      end
    end
  end

  describe 'POST /token (grant_type="refresh_token")' do
    let_it_be(:user) { create(:user) }

    let(:params) { {client_id:, grant_type:, refresh_token:}.compact }
    let(:grant_type) { "refresh_token" }
    let(:refresh_token) { TokenAuthority::JsonWebToken.encode(attributes_for(:token_authority_refresh_token, token_authority_session:)) }
    let!(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

    shared_examples "requires a valid refresh_token param" do
      let(:refresh_token) { "foobar" }

      it "responds with HTTP status bad request and error unsupported_grant_type as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end
    end

    shared_examples "does not refresh a revoked session" do
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "revoked") }

      it "responds with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end

      it "logs the refresh replay attack details" do
        logger_spy = instance_spy(ActiveSupport::Logger)
        allow(Rails).to receive(:logger).and_return(logger_spy)
        call_endpoint
        expect(logger_spy)
          .to have_received(:warn)
          .with(
            I18n.t(
              "token_authority.errors.revoked_session",
              client_id: token_authority_authorization_grant.token_authority_client.public_id,
              refreshed_session_id: token_authority_session.id,
              revoked_session_id: token_authority_session.id,
              user_id: user.id
            )
          )
      end
    end

    shared_examples "does not refresh an already refreshed session" do
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed") }

      it "responds with HTTP status bad request and error invalid_request as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "invalid_request"})
        end
      end

      it "logs the refresh replay attack details" do
        active_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:)
        logger_spy = instance_spy(ActiveSupport::Logger)
        allow(Rails).to receive(:logger).and_return(logger_spy)
        call_endpoint
        expect(logger_spy)
          .to have_received(:warn)
          .with(
            I18n.t(
              "token_authority.errors.revoked_session",
              client_id: token_authority_authorization_grant.token_authority_client.public_id,
              refreshed_session_id: token_authority_session.id,
              revoked_session_id: active_token_authority_session.id,
              user_id: user.id
            )
          )
      end
    end

    context "when the client type is public" do
      subject(:call_endpoint) { post token_authority.refresh_session_path, params: }

      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

      let(:client_id) { token_authority_client.public_id }

      it_behaves_like "requires a valid client_id param"
      it_behaves_like "generates an OAuth session"
      it_behaves_like "requires a valid refresh_token param"
      it_behaves_like "does not refresh a revoked session"
      it_behaves_like "does not refresh an already refreshed session"
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

      let(:client_id) { nil }

      include_context "with an authenticated client", :post, :token_authority_refresh_session_path

      it_behaves_like "an endpoint that requires client authentication"
      it_behaves_like "does not require a valid client_id param"
      it_behaves_like "generates an OAuth session"
      it_behaves_like "requires a valid refresh_token param"
      it_behaves_like "does not refresh a revoked session"
      it_behaves_like "does not refresh an already refreshed session"
    end

    context "when using a URL-based client" do
      subject(:call_endpoint) { post token_authority.refresh_session_path, params: }

      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:token_authority_authorization_grant) do
        create(:token_authority_authorization_grant, user:, token_authority_client: nil, client_id_url: client_id_url)
      end
      let(:client_id) { client_id_url }

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it_behaves_like "generates an OAuth session"
      it_behaves_like "requires a valid refresh_token param"
    end
  end

  describe "POST /token (grant_type={ NOT `authorization_code` or `refresh_token` })" do
    let_it_be(:user) { create(:user) }

    let(:params) { {code:, code_verifier:, grant_type:}.compact }
    let(:grant_type) { "foobar" }
    let(:code_verifier) { "code_verifier" }
    let(:code) { token_authority_authorization_grant.public_id }

    context "when the client type is public" do
      subject(:call_endpoint) { post token_authority.create_session_path, params: }

      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

      let(:client_id) { token_authority_client.public_id }

      it "responds with HTTP status bad request and error unsupported_grant_type as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "unsupported_grant_type"})
        end
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:) }

      let(:client_id) { nil }

      include_context "with an authenticated client", :post, :token_authority_create_session_path

      it "responds with HTTP status bad request and error unsupported_grant_type as JSON" do
        call_endpoint
        aggregate_failures do
          expect(response).to have_http_status(:bad_request)
          expect(response.parsed_body).to eq({"error" => "unsupported_grant_type"})
        end
      end
    end
  end

  describe "POST /revoke (token_type_hint={ NOT `access_token` or `refresh_token` })" do
    let_it_be(:user) { create(:user) }

    let(:params) { {token:, token_type_hint: "foobar", client_id:}.compact }
    let(:token) { TokenAuthority::JsonWebToken.encode(attributes_for(:token_authority_access_token, token_authority_session:)) }
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

    context "when the client type is public" do
      subject(:call_endpoint) { post token_authority.revoke_path, params: }

      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:, redeemed: true) }

      let(:client_id) { token_authority_client.public_id }

      it "invokes the domain logic for revocation via generic lookup" do
        allow(TokenAuthority::Session).to receive(:revoke_for_token).and_return(true)
        call_endpoint
        expect(TokenAuthority::Session).to have_received(:revoke_for_token)
      end

      it "responds with HTTP status ok" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:, redeemed: true) }

      let(:client_id) { nil }

      include_context "with an authenticated client", :post, :token_authority_revoke_path

      it_behaves_like "an endpoint that requires client authentication"

      it "invokes the domain logic for revocation via generic lookup" do
        allow(TokenAuthority::Session).to receive(:revoke_for_token).and_return(true)
        call_endpoint
        expect(TokenAuthority::Session).to have_received(:revoke_for_token)
      end

      it "responds with HTTP status ok" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end
  end

  describe "POST /revoke (token_type_hint=access_token)" do
    let_it_be(:user) { create(:user) }

    let(:params) { {token:, token_type_hint: "access_token", client_id:}.compact }
    let(:token) { TokenAuthority::JsonWebToken.encode(attributes_for(:token_authority_access_token, token_authority_session:)) }
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

    context "when the client type is public" do
      subject(:call_endpoint) { post token_authority.revoke_access_token_path, params: }

      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:, redeemed: true) }

      let(:client_id) { token_authority_client.public_id }

      it "invokes the domain logic for revocation via access token lookup" do
        allow(TokenAuthority::Session).to receive(:revoke_for_access_token).and_return(true)
        call_endpoint
        expect(TokenAuthority::Session).to have_received(:revoke_for_access_token)
      end

      it "responds with HTTP status ok" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, redeemed: true) }

      let(:client_id) { nil }

      include_context "with an authenticated client", :post, :token_authority_revoke_access_token_path

      it_behaves_like "an endpoint that requires client authentication"

      it "invokes the domain logic for revocation via access token lookup" do
        allow(TokenAuthority::Session).to receive(:revoke_for_access_token).and_return(true)
        call_endpoint
        expect(TokenAuthority::Session).to have_received(:revoke_for_access_token)
      end

      it "responds with HTTP status ok" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end
  end

  describe "POST /revoke (token_type_hint=refresh_token})" do
    let_it_be(:user) { create(:user) }

    let(:params) { {token:, token_type_hint: "refresh_token", client_id:}.compact }
    let(:token) { TokenAuthority::JsonWebToken.encode(attributes_for(:token_authority_refresh_token, token_authority_session:)) }
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

    context "when the client type is public" do
      subject(:call_endpoint) { post token_authority.revoke_refresh_token_path, params: }

      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, token_authority_client:, redeemed: true) }

      let(:client_id) { token_authority_client.public_id }

      it "invokes the domain logic for revocation via refresh token lookup" do
        allow(TokenAuthority::Session).to receive(:revoke_for_refresh_token).and_return(true)
        call_endpoint
        expect(TokenAuthority::Session).to have_received(:revoke_for_refresh_token)
      end

      it "responds with HTTP status ok" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end

    context "when the client type is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, user:, redeemed: true) }

      let(:client_id) { nil }

      include_context "with an authenticated client", :post, :token_authority_revoke_refresh_token_path

      it_behaves_like "an endpoint that requires client authentication"

      it "invokes the domain logic for revocation via refresh token lookup" do
        allow(TokenAuthority::Session).to receive(:revoke_for_refresh_token).and_return(true)
        call_endpoint
        expect(TokenAuthority::Session).to have_received(:revoke_for_refresh_token)
      end

      it "responds with HTTP status ok" do
        call_endpoint
        expect(response).to have_http_status(:ok)
      end
    end
  end

  private

  def token_authority_create_session_path
    token_authority.create_session_path
  end

  def token_authority_refresh_session_path
    token_authority.refresh_session_path
  end

  def token_authority_revoke_path
    token_authority.revoke_path
  end

  def token_authority_revoke_access_token_path
    token_authority.revoke_access_token_path
  end

  def token_authority_revoke_refresh_token_path
    token_authority.revoke_refresh_token_path
  end
end
