# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::RefreshTokenRequest, type: :model do
  subject(:model) { described_class.new(**attrs) }

  let(:attrs) do
    {token:, resources:, client_id:, scope:}.compact
  end

  let(:token) { build(:token_authority_refresh_token, token_authority_session:) }
  let(:resources) { nil }
  let(:client_id) { nil }
  let(:scope) { nil }

  describe "validations" do
    context "when no token is provided" do
      let(:token_authority_session) { create(:token_authority_session) }
      let(:token) { nil }

      it "adds a token error and skips other validations" do
        aggregate_failures do
          expect(model).not_to be_valid
          expect(model.errors.count).to eq(1)
          expect(model.errors.first.attribute).to eq(:token)
          expect(model.errors.first.type).to eq(:blank)
        end
      end
    end

    context "when token does not map to a session" do
      let(:token_authority_session) { create(:token_authority_session) }
      let(:token) { build(:token_authority_refresh_token, token_authority_session:, jti: "non-existent-jti") }

      it "adds a token error" do
        aggregate_failures do
          expect(model).not_to be_valid
          expect(model.errors[:token]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.token.session_not_found")
          )
        end
      end
    end

    context "when token maps to a valid session" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, token_authority_client:, redeemed: true) }
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

      it "is valid" do
        expect(model).to be_valid
      end
    end

    context "with RFC 8707 resource indicators" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:token_authority_authorization_grant) do
        create(:token_authority_authorization_grant, token_authority_client:, redeemed: true, resources: granted_resources)
      end
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
      let(:granted_resources) { ["https://api1.example.com", "https://api2.example.com"] }
      let(:configured_resources) do
        {
          "https://api1.example.com" => "API 1",
          "https://api2.example.com" => "API 2",
          "https://api3.example.com" => "API 3"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:resource_registry).and_return(configured_resources)
        allow(TokenAuthority.config).to receive(:rfc_8707_enabled?).and_return(true)
      end

      context "when resources is nil" do
        let(:resources) { nil }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when resources is an empty array" do
        let(:resources) { [] }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when resources is a subset of granted resources" do
        let(:resources) { ["https://api1.example.com"] }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when resources equals granted resources" do
        let(:resources) { ["https://api1.example.com", "https://api2.example.com"] }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when resources is not a subset of granted resources" do
        let(:resources) { ["https://api3.example.com"] }

        it "is invalid with not_subset error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.resources.not_subset")
          )
        end
      end

      context "when resources contains invalid URIs" do
        let(:resources) { ["not-a-valid-uri"] }

        it "is invalid with invalid_uri error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.resources.invalid_uri")
          )
        end
      end

      context "when resources are not in the configured resources" do
        let(:resources) { ["https://not-configured.example.com"] }

        it "is invalid with not_allowed error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.resources.not_allowed")
          )
        end
      end

      context "when RFC 8707 is disabled (no resources configured)" do
        before do
          allow(TokenAuthority.config).to receive(:resource_registry).and_return({})
          allow(TokenAuthority.config).to receive(:rfc_8707_enabled?).and_return(false)
        end

        context "when no resources are provided" do
          let(:resources) { nil }

          it "is valid" do
            expect(model).to be_valid
          end
        end

        context "when resources are provided" do
          let(:resources) { ["https://api1.example.com"] }

          it "is invalid with not_allowed error" do
            expect(model).not_to be_valid
            expect(model.errors[:resources]).to include(
              I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.resources.not_allowed")
            )
          end
        end
      end
    end

    context "with scopes" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:token_authority_authorization_grant) do
        create(:token_authority_authorization_grant, token_authority_client:, redeemed: true, scopes: granted_scopes)
      end
      let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
      let(:granted_scopes) { ["read", "write"] }
      let(:configured_scopes) do
        {
          "read" => "Read access",
          "write" => "Write access",
          "delete" => "Delete access"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return(configured_scopes)
      end

      context "when scope is nil" do
        let(:scope) { nil }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when scope is a subset of granted scopes" do
        let(:scope) { "read" }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when scope equals granted scopes" do
        let(:scope) { "read write" }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when scope is not a subset of granted scopes" do
        let(:scope) { "delete" }

        it "is invalid with not_subset error" do
          expect(model).not_to be_valid
          expect(model.errors[:scope]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.scope.not_subset")
          )
        end
      end

      context "when scope contains invalid tokens" do
        let(:scope) { "read \"invalid" }

        it "is invalid with invalid error" do
          expect(model).not_to be_valid
          expect(model.errors[:scope]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.scope.invalid")
          )
        end
      end

      context "when scope is not in the configured scopes" do
        let(:scope) { "not_configured" }

        it "is invalid with not_allowed error" do
          expect(model).not_to be_valid
          expect(model.errors[:scope]).to include(
            I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.scope.not_allowed")
          )
        end
      end

      context "when scopes are disabled (no scopes configured)" do
        before do
          allow(TokenAuthority.config).to receive(:scopes).and_return(nil)
        end

        context "when no scope is provided" do
          let(:scope) { nil }

          it "is valid" do
            expect(model).to be_valid
          end
        end

        context "when scope is provided" do
          let(:scope) { "read" }

          it "is invalid with not_allowed error" do
            expect(model).not_to be_valid
            expect(model.errors[:scope]).to include(
              I18n.t("activemodel.errors.models.token_authority/refresh_token_request.attributes.scope.not_allowed")
            )
          end
        end
      end
    end
  end

  describe "#effective_resources" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let(:token_authority_authorization_grant) do
      create(:token_authority_authorization_grant, token_authority_client:, redeemed: true, resources: granted_resources)
    end
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
    let(:granted_resources) { ["https://api1.example.com", "https://api2.example.com"] }

    context "when resources is provided" do
      let(:resources) { ["https://api1.example.com"] }

      it "returns the requested resources" do
        expect(model.effective_resources).to eq(["https://api1.example.com"])
      end
    end

    context "when resources is nil" do
      let(:resources) { nil }

      it "returns the granted resources from the grant" do
        expect(model.effective_resources).to eq(granted_resources)
      end
    end

    context "when resources is an empty array" do
      let(:resources) { [] }

      it "returns the granted resources from the grant" do
        expect(model.effective_resources).to eq(granted_resources)
      end
    end

    context "when no resources were granted" do
      let(:granted_resources) { [] }
      let(:resources) { nil }

      it "returns an empty array" do
        expect(model.effective_resources).to eq([])
      end
    end
  end

  describe "#effective_scopes" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let(:token_authority_authorization_grant) do
      create(:token_authority_authorization_grant, token_authority_client:, redeemed: true, scopes: granted_scopes)
    end
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
    let(:granted_scopes) { ["read", "write"] }

    context "when scope is provided" do
      let(:scope) { "read" }

      it "returns the requested scopes" do
        expect(model.effective_scopes).to eq(["read"])
      end
    end

    context "when scope is nil" do
      let(:scope) { nil }

      it "returns the granted scopes from the grant" do
        expect(model.effective_scopes).to eq(granted_scopes)
      end
    end

    context "when no scopes were granted" do
      let(:granted_scopes) { [] }
      let(:scope) { nil }

      it "returns an empty array" do
        expect(model.effective_scopes).to eq([])
      end
    end
  end

  describe "#token_authority_session" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, token_authority_client:, redeemed: true) }
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

    it "returns the session matching the token's JTI" do
      expect(model.token_authority_session).to eq(token_authority_session)
    end

    context "when token is nil" do
      let(:token) { nil }

      it "returns nil" do
        expect(model.token_authority_session).to be_nil
      end
    end
  end

  describe "#resolved_client_id" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, token_authority_client:, redeemed: true) }
    let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

    context "when client_id param is provided" do
      let(:client_id) { "explicit-client-id" }

      it "returns the provided client_id" do
        expect(model.resolved_client_id).to eq("explicit-client-id")
      end
    end

    context "when client_id param is not provided" do
      let(:client_id) { nil }

      it "returns the client_id from the grant's client" do
        expect(model.resolved_client_id).to eq(token_authority_client.public_id)
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
        create(:token_authority_authorization_grant, token_authority_client: nil, client_id_url: client_id_url, redeemed: true)
      end

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it "returns the URL-based client_id" do
        expect(model.resolved_client_id).to eq(client_id_url)
      end
    end
  end
end
