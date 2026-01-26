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
      state:,
      resources:
    }
  end

  let(:client_id) { initial_attrs[:client_id] }
  let(:code_challenge) { initial_attrs[:code_challenge] }
  let(:code_challenge_method) { initial_attrs[:code_challenge_method] }
  let(:redirect_uri) { initial_attrs[:redirect_uri] }
  let(:response_type) { initial_attrs[:response_type] }
  let(:state) { initial_attrs[:state] }
  let(:resources) { nil }

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
          expect(model).to allow_value(token_authority_client.primary_redirect_uri).for(:redirect_uri)
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

    context "when TokenAuthority client is a URL-based ClientMetadataDocument" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:token_authority_client) { TokenAuthority::ClientMetadataDocument.new(metadata) }
      let(:client_id) { client_id_url }
      let(:redirect_uri) { "https://example.com/callback" }

      it_behaves_like "validates response_type param"
      it_behaves_like "validates PKCE params"

      it "validates client_id matches the URL" do
        aggregate_failures do
          expect(model).to be_valid
          model.client_id = "https://other.example.com/client"
          expect(model).not_to be_valid
          expect(model.errors[:client_id]).to include(I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.client_id.mismatched"))
        end
      end

      it "requires client_id to be present" do
        model.client_id = nil
        expect(model).not_to be_valid
      end

      it "validates redirect_uri is registered" do
        aggregate_failures do
          expect(model).to allow_value("https://example.com/callback").for(:redirect_uri)
          expect(model).not_to allow_value("https://evil.com/callback").for(:redirect_uri)
        end
      end
    end

    context "with RFC 8707 resource indicators" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:client_id) { token_authority_client.public_id }
      let(:configured_resources) do
        {
          "https://api.example.com" => "Main API",
          "https://api2.example.com" => "Secondary API"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:resource_registry).and_return(configured_resources)
        allow(TokenAuthority.config).to receive(:resources_enabled?).and_return(true)
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

      context "when resources contains valid URIs in the allowlist" do
        let(:resources) { ["https://api.example.com", "https://api2.example.com"] }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when resources contains invalid URIs" do
        let(:resources) { ["not-a-valid-uri"] }

        it "is invalid with invalid_uri error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.resources.invalid_uri")
          )
        end
      end

      context "when resources contains a URI with fragment" do
        let(:resources) { ["https://api.example.com#fragment"] }

        it "is invalid with invalid_uri error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.resources.invalid_uri")
          )
        end
      end

      context "when require_resource is true" do
        before do
          allow(TokenAuthority.config).to receive(:require_resource).and_return(true)
        end

        context "when resources is empty" do
          let(:resources) { [] }

          it "is invalid with required error" do
            expect(model).not_to be_valid
            expect(model.errors[:resources]).to include(
              I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.resources.required")
            )
          end
        end

        context "when resources is provided and in allowlist" do
          let(:resources) { ["https://api.example.com"] }

          it "is valid" do
            expect(model).to be_valid
          end
        end
      end

      context "when resources are not in the allowlist" do
        let(:resources) { ["https://not-allowed.example.com"] }

        it "is invalid with not_allowed error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.resources.not_allowed")
          )
        end
      end

      context "when resource URIs have mismatched trailing slashes" do
        before do
          # Config has trailing slash, request does not
          allow(TokenAuthority.config).to receive(:resource_registry).and_return({
            "https://api.example.com" => "REST API"
          })
        end

        context "when request has no trailing slash but config did" do
          let(:resources) { ["https://api.example.com"] }

          it "is valid due to URI normalization" do
            expect(model).to be_valid
          end
        end

        context "when request has trailing slash but config did not" do
          let(:resources) { ["https://api.example.com/"] }

          it "is valid due to URI normalization" do
            expect(model).to be_valid
          end
        end
      end

      context "when RFC 8707 is disabled (no resources configured)" do
        before do
          allow(TokenAuthority.config).to receive(:resource_registry).and_return({})
          allow(TokenAuthority.config).to receive(:resources_enabled?).and_return(false)
        end

        context "when no resources are provided" do
          let(:resources) { nil }

          it "is valid" do
            expect(model).to be_valid
          end
        end

        context "when resources are provided" do
          let(:resources) { ["https://api.example.com"] }

          it "is invalid with not_allowed error" do
            expect(model).not_to be_valid
            expect(model.errors[:resources]).to include(
              I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.resources.not_allowed")
            )
          end
        end
      end
    end

    context "with scope support" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:scope) { nil }
      let(:model) do
        described_class.new(
          token_authority_client: token_authority_client,
          client_id: token_authority_client.public_id,
          code_challenge: "challenge",
          code_challenge_method: "S256",
          redirect_uri: token_authority_client.primary_redirect_uri,
          response_type: "code",
          state: "some-state",
          scope: scope
        )
      end

      before do
        allow(TokenAuthority.config).to receive(:scopes).and_return(
          {"read" => "Read access", "write" => "Write access"}
        )
        allow(TokenAuthority.config).to receive(:scopes_enabled?).and_return(true)
        allow(TokenAuthority.config).to receive(:require_scope).and_return(false)
      end

      context "when scope is nil" do
        let(:scope) { nil }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when scope is an empty array" do
        let(:scope) { [] }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when scope is valid and allowed" do
        let(:scope) { ["read", "write"] }

        it "is valid" do
          expect(model).to be_valid
        end
      end

      context "when scope contains invalid token" do
        let(:scope) { ["read", "invalid scope"] }

        it "is invalid with invalid error" do
          expect(model).not_to be_valid
          expect(model.errors[:scope]).to include(
            I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.scope.invalid")
          )
        end
      end

      context "when scope contains disallowed scope" do
        let(:scope) { ["read", "admin"] }

        it "is invalid with not_allowed error" do
          expect(model).not_to be_valid
          expect(model.errors[:scope]).to include(
            I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.scope.not_allowed")
          )
        end
      end

      context "when require_scope is true" do
        before do
          allow(TokenAuthority.config).to receive(:require_scope).and_return(true)
        end

        context "when scope is empty" do
          let(:scope) { [] }

          it "is invalid with required error" do
            expect(model).not_to be_valid
            expect(model.errors[:scope]).to include(
              I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.scope.required")
            )
          end
        end
      end

      context "when scopes are disabled (no scopes configured)" do
        before do
          allow(TokenAuthority.config).to receive(:scopes).and_return(nil)
          allow(TokenAuthority.config).to receive(:scopes_enabled?).and_return(false)
        end

        context "when no scope is provided" do
          let(:scope) { nil }

          it "is valid" do
            expect(model).to be_valid
          end
        end

        context "when scope is provided" do
          let(:scope) { ["read"] }

          it "is invalid with not_allowed error" do
            expect(model).not_to be_valid
            expect(model.errors[:scope]).to include(
              I18n.t("activemodel.errors.models.token_authority/authorization_request.attributes.scope.not_allowed")
            )
          end
        end
      end
    end
  end

  describe ".from_internal_state_token" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let(:authorization_request) do
      described_class.new(
        token_authority_client: token_authority_client,
        client_id: token_authority_client.public_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: token_authority_client.primary_redirect_uri,
        response_type: "code",
        state: "some-state"
      )
    end
    let(:token) { authorization_request.to_internal_state_token }

    context "with a registered client" do
      it "reconstructs the authorization request" do
        result = described_class.from_internal_state_token(token)

        aggregate_failures do
          expect(result.token_authority_client).to eq(token_authority_client)
          expect(result.client_id).to eq(token_authority_client.public_id)
          expect(result.code_challenge).to eq("challenge")
          expect(result.state).to eq("some-state")
        end
      end
    end

    context "with a URL-based client" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:url_based_client) { TokenAuthority::ClientMetadataDocument.new(metadata) }
      let(:authorization_request) do
        described_class.new(
          token_authority_client: url_based_client,
          client_id: client_id_url,
          code_challenge: "challenge",
          code_challenge_method: "S256",
          redirect_uri: "https://example.com/callback",
          response_type: "code",
          state: "some-state"
        )
      end

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it "reconstructs the authorization request with a ClientMetadataDocument" do
        result = described_class.from_internal_state_token(token)

        aggregate_failures do
          expect(result.token_authority_client).to be_a(TokenAuthority::ClientMetadataDocument)
          expect(result.token_authority_client.public_id).to eq(client_id_url)
          expect(result.client_id).to eq(client_id_url)
        end
      end
    end

    context "when client cannot be resolved" do
      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .and_raise(TokenAuthority::ClientNotFoundError)
      end

      it "returns an invalid authorization request with nil client" do
        result = described_class.from_internal_state_token(token)

        aggregate_failures do
          expect(result.token_authority_client).to be_nil
          expect(result).not_to be_valid
        end
      end
    end

    context "with resources" do
      let(:authorization_request) do
        described_class.new(
          token_authority_client: token_authority_client,
          client_id: token_authority_client.public_id,
          code_challenge: "challenge",
          code_challenge_method: "S256",
          redirect_uri: token_authority_client.primary_redirect_uri,
          response_type: "code",
          state: "some-state",
          resources: ["https://api.example.com", "https://api2.example.com"]
        )
      end

      it "preserves resources through serialization and deserialization" do
        result = described_class.from_internal_state_token(token)

        expect(result.resources).to eq(["https://api.example.com", "https://api2.example.com"])
      end
    end

    context "with scope" do
      let(:authorization_request) do
        described_class.new(
          token_authority_client: token_authority_client,
          client_id: token_authority_client.public_id,
          code_challenge: "challenge",
          code_challenge_method: "S256",
          redirect_uri: token_authority_client.primary_redirect_uri,
          response_type: "code",
          state: "some-state",
          scope: ["read", "write"]
        )
      end

      it "preserves scope through serialization and deserialization" do
        result = described_class.from_internal_state_token(token)

        expect(result.scope).to eq(["read", "write"])
      end
    end
  end

  describe "#to_h" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let(:authorization_request) do
      described_class.new(
        token_authority_client: token_authority_client,
        client_id: token_authority_client.public_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: token_authority_client.primary_redirect_uri,
        response_type: "code",
        state: "some-state",
        resources: resources
      )
    end

    context "when resources is nil" do
      let(:resources) { nil }

      it "includes empty array for resources" do
        expect(authorization_request.to_h[:resources]).to eq([])
      end
    end

    context "when resources is provided" do
      let(:resources) { ["https://api.example.com"] }

      it "includes resources in the hash" do
        expect(authorization_request.to_h[:resources]).to eq(["https://api.example.com"])
      end
    end
  end

  describe "#to_h scope handling" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let(:authorization_request) do
      described_class.new(
        token_authority_client: token_authority_client,
        client_id: token_authority_client.public_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: token_authority_client.primary_redirect_uri,
        response_type: "code",
        state: "some-state",
        scope: scope
      )
    end

    context "when scope is nil" do
      let(:scope) { nil }

      it "includes empty array for scope" do
        expect(authorization_request.to_h[:scope]).to eq([])
      end
    end

    context "when scope is provided" do
      let(:scope) { ["read", "write"] }

      it "includes scope in the hash" do
        expect(authorization_request.to_h[:scope]).to eq(["read", "write"])
      end
    end
  end
end
