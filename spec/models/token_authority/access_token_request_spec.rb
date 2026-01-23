# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::AccessTokenRequest, type: :model do
  subject(:model) { described_class.new(**attrs) }

  let_it_be(:initial_attrs) { attributes_for(:token_authority_access_token_request) }

  let(:attrs) do
    {code_verifier:, token_authority_authorization_grant:, redirect_uri:, resources:}.compact
  end

  let(:code_verifier) { initial_attrs[:code_verifier] }
  let(:redirect_uri) { initial_attrs[:redirect_uri] }
  let(:resources) { nil }

  describe "validations" do
    shared_examples "validates token_authority_authorization_grant is present" do
      it "allows valid token_authority_authorization_grant" do
        expect(model).to allow_value(token_authority_authorization_grant).for(:token_authority_authorization_grant)
      end

      it "validates token_authority_authorization_grant is present" do
        expect(model).not_to allow_value(nil).for(:token_authority_authorization_grant)
      end

      it "validates token_authority_authorization_grant to map to a valid authorization grant" do
        expect(model).not_to allow_value("invalid-token-authority-authorization-grant").for(:token_authority_authorization_grant)
      end
    end

    shared_examples "code_verifier is required" do
      it "requires code_verifier param" do
        model.code_verifier = nil
        expect(model).not_to be_valid
      end
    end

    shared_examples "code_verifier is not required" do
      it "does not require code_verifier param" do
        model.code_verifier = nil
        expect(model).to be_valid
      end
    end

    shared_examples "validates code_verifier matches code_challenge" do
      context "when code_verifier is not valid" do
        it "adds an error" do
          model.code_verifier = "not-valid"
          expect(model).not_to be_valid
        end
      end

      context "when code_verifier is valid" do
        it "does not add an error" do
          model.code_verifier = "code_verifier"
          expect(model).to be_valid
        end
      end
    end

    shared_examples "redirect_uri is required" do
      it "requires redirect_uri param" do
        model.redirect_uri = nil
        expect(model).not_to be_valid
      end
    end

    shared_examples "redirect_uri is not required" do
      it "does not require redirect_uri param" do
        model.redirect_uri = nil
        expect(model).to be_valid
      end
    end

    shared_examples "validates redirect_uri param" do
      it "validates redirect_uri param" do
        aggregate_failures do
          expect(model).to allow_value(token_authority_client.primary_redirect_uri).for(:redirect_uri)
          expect(model).not_to allow_value("invalid-redirect-uri").for(:redirect_uri)
        end
      end
    end

    context "when no TokenAuthority authorization grant is provided" do
      let(:token_authority_authorization_grant) { nil }

      it "adds a token_authority_client error to the model and skips other validations" do
        aggregate_failures do
          expect(model).not_to be_valid
          expect(model.errors.count).to eq(1)
          expect(model.errors.first.attribute).to eq(:token_authority_authorization_grant)
          expect(model.errors.first.type).to eq(:invalid)
        end
      end
    end

    context "when TokenAuthority client is public" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, token_authority_client:) }

      let(:client_id) { token_authority_client.id }

      it_behaves_like "validates token_authority_authorization_grant is present"
      it_behaves_like "code_verifier is required"
      it_behaves_like "validates code_verifier matches code_challenge"
      it_behaves_like "redirect_uri is required"
      it_behaves_like "validates redirect_uri param"
    end

    context "when TokenAuthority client is confidential" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "confidential") }

      let(:token_authority_authorization_grant) do
        create(
          :token_authority_authorization_grant,
          code_challenge:,
          code_challenge_method:,
          redirect_uri: challenge_redirect_uri,
          token_authority_client:
        )
      end

      let(:code_verifier) { nil }
      let(:redirect_uri) { nil }
      let(:code_challenge) { nil }
      let(:code_challenge_method) { nil }
      let(:challenge_redirect_uri) { nil }

      it_behaves_like "validates token_authority_authorization_grant is present"
      it_behaves_like "code_verifier is not required"
      it_behaves_like "redirect_uri is not required"

      context "when a code_verifier param is provided and code_challenge was provided in the authorization request" do
        let(:code_verifier) { "code_verifier" }
        let(:code_challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false) }
        let(:code_challenge_method) { "S256" }

        it_behaves_like "validates code_verifier matches code_challenge"
      end

      context "when a code_verifier param is provided and code_challenge was not provided in authorization request" do
        let(:code_verifier) { "code_verifier" }

        it "adds an error" do
          expect(model).not_to be_valid
        end
      end

      context "when redirect_uri is provided but not provided in authorization request" do
        let(:challenge_redirect_uri) { token_authority_client.primary_redirect_uri }

        it "adds an error" do
          expect(model).not_to be_valid
        end
      end

      context "when redirect_uri is provided in both the access token and authorization requests" do
        let(:redirect_uri) { token_authority_client.primary_redirect_uri }
        let(:challenge_redirect_uri) { token_authority_client.primary_redirect_uri }

        it_behaves_like "validates redirect_uri param"
      end
    end

    context "when authorization grant uses a URL-based client" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:token_authority_authorization_grant) do
        create(
          :token_authority_authorization_grant,
          token_authority_client: nil,
          client_id_url: client_id_url,
          code_challenge: Base64.urlsafe_encode64(Digest::SHA256.digest("code_verifier"), padding: false),
          code_challenge_method: "S256",
          redirect_uri: "https://example.com/callback"
        )
      end
      let(:code_verifier) { "code_verifier" }
      let(:redirect_uri) { "https://example.com/callback" }

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it "resolves the client via resolved_client and validates as public client" do
        expect(model).to be_valid
      end

      it "requires code_verifier for URL-based clients (always public)" do
        model.code_verifier = nil
        expect(model).not_to be_valid
      end

      it "requires redirect_uri for URL-based clients (always public)" do
        model.redirect_uri = nil
        expect(model).not_to be_valid
      end
    end

    context "with RFC 8707 resource indicators" do
      let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
      let(:token_authority_authorization_grant) do
        create(:token_authority_authorization_grant, token_authority_client:).tap do |grant|
          grant.token_authority_challenge.update!(resources: granted_resources)
        end
      end
      let(:granted_resources) { ["https://api1.example.com", "https://api2.example.com"] }
      let(:configured_resources) do
        {
          "https://api1.example.com" => "API 1",
          "https://api2.example.com" => "API 2",
          "https://api3.example.com" => "API 3"
        }
      end

      before do
        allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(configured_resources)
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
            I18n.t("activemodel.errors.models.token_authority/access_token_request.attributes.resources.not_subset")
          )
        end
      end

      context "when resources contains invalid URIs" do
        let(:resources) { ["not-a-valid-uri"] }

        it "is invalid with invalid_uri error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/access_token_request.attributes.resources.invalid_uri")
          )
        end
      end

      context "when resources are not in the configured resources" do
        let(:resources) { ["https://not-configured.example.com"] }

        it "is invalid with not_allowed error" do
          expect(model).not_to be_valid
          expect(model.errors[:resources]).to include(
            I18n.t("activemodel.errors.models.token_authority/access_token_request.attributes.resources.not_allowed")
          )
        end
      end

      context "when RFC 8707 is disabled (no resources configured)" do
        before do
          allow(TokenAuthority.config).to receive(:rfc_8707_resources).and_return(nil)
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
              I18n.t("activemodel.errors.models.token_authority/access_token_request.attributes.resources.not_allowed")
            )
          end
        end
      end
    end
  end

  describe "#effective_resources" do
    let_it_be(:token_authority_client) { create(:token_authority_client, client_type: "public") }
    let(:token_authority_authorization_grant) do
      create(:token_authority_authorization_grant, token_authority_client:).tap do |grant|
        grant.token_authority_challenge.update!(resources: granted_resources)
      end
    end
    let(:granted_resources) { ["https://api1.example.com", "https://api2.example.com"] }

    context "when resources is provided" do
      let(:resources) { ["https://api1.example.com"] }

      it "returns the requested resources" do
        expect(model.effective_resources).to eq(["https://api1.example.com"])
      end
    end

    context "when resources is nil" do
      let(:resources) { nil }

      it "returns the granted resources from the challenge" do
        expect(model.effective_resources).to eq(granted_resources)
      end
    end

    context "when resources is an empty array" do
      let(:resources) { [] }

      it "returns the granted resources from the challenge" do
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
end
