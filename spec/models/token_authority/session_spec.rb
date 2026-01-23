# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::Session, type: :model do
  subject(:model) { build(:token_authority_session) }

  describe "validations" do
    describe "access_token_jti" do
      it { is_expected.to validate_presence_of(:access_token_jti) }

      it "validates values for access_token_jti" do
        aggregate_failures do
          expect(model).to validate_uniqueness_of(:access_token_jti)
          expect(model).to allow_value(SecureRandom.uuid).for(:access_token_jti)
          expect(model).not_to allow_value("foobar").for(:access_token_jti)
        end
      end
    end

    describe "refresh_token_jti" do
      it { is_expected.to validate_presence_of(:refresh_token_jti) }

      it "validates values for refresh_token_jti" do
        aggregate_failures do
          expect(model).to validate_uniqueness_of(:refresh_token_jti)
          expect(model).to allow_value(SecureRandom.uuid).for(:refresh_token_jti)
          expect(model).not_to allow_value("foobar").for(:refresh_token_jti)
        end
      end
    end

    describe "status" do
      it "validates values for status" do
        aggregate_failures do
          expect(model).to allow_value("created").for(:status)
          expect(model).to allow_value("expired").for(:status)
          expect(model).to allow_value("refreshed").for(:status)
          expect(model).to allow_value("revoked").for(:status)
        end
      end

      it "raises an ArgumentError when an invalid status is provided" do
        expect { model.status = "foobar" }.to raise_error(ArgumentError)
      end
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:token_authority_authorization_grant) }
  end

  describe "#refresh" do
    subject(:method_call) { token_authority_session.refresh(token: token_authority_refresh_token, client_id:) }

    let_it_be(:token_authority_client) { create(:token_authority_client) }
    let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, redeemed: true, token_authority_client:) }

    let!(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
    let(:token_authority_refresh_token) { build(:token_authority_refresh_token, token_authority_session:) }
    let(:client_id) { token_authority_client.public_id }

    it "instruments the refresh operation" do
      expect { method_call }.to instrument("token_authority.session.refresh")
    end

    it_behaves_like "a model that creates TokenAuthority sessions"

    describe "RFC 8707 resource indicators" do
      let(:method_call_with_resources) do
        token_authority_session.refresh(token: token_authority_refresh_token, client_id:, resources:)
      end

      it_behaves_like "a model that creates TokenAuthority sessions with RFC 8707 resources"
    end

    describe "scopes" do
      let(:method_call_with_scopes) do
        token_authority_session.refresh(token: token_authority_refresh_token, client_id:, scopes:)
      end

      it_behaves_like "a model that creates TokenAuthority sessions with scopes"
    end

    context "when the TokenAuthority session is in created status" do
      it "refreshes the TokenAuthority session" do
        aggregate_failures do
          expect { method_call }.to change(token_authority_session, :status).from("created").to("refreshed")
          expect(described_class.count).to eq(2)
        end
      end
    end

    context "when the provided token contains a JTI that does not match the refresh token JTI of the TokenAuthority session" do
      let(:token_authority_refresh_token) { build(:token_authority_refresh_token, token_authority_session:, jti: "foobar") }

      it "does not refresh the TokenAuthority session and raises a TokenAuthority::ServerError" do
        aggregate_failures do
          expect { method_call }.to raise_error(TokenAuthority::ServerError, I18n.t("token_authority.errors.mismatched_refresh_token"))
          expect(described_class.count).to eq(1)
        end
      end
    end

    context "when the provided token has invalid claims" do
      let(:token_authority_refresh_token) { build(:token_authority_refresh_token, token_authority_session:, exp: 14.days.ago.to_i) }

      it "does not refresh the session and raises a TokenAuthority::InvalidGrantError" do
        aggregate_failures do
          expect { method_call }.to raise_error(TokenAuthority::InvalidGrantError)
          expect(described_class.count).to eq(1)
        end
      end
    end

    context "when the TokenAuthority session has already been refreshed" do
      let_it_be(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed") }

      context "with an active TokenAuthority session existing for authorization grant" do
        it "revokes the TokenAuthority session and raises a TokenAuthority::RevokedSessionError" do
          active_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:)
          aggregate_failures do
            expect { method_call }.to raise_error(TokenAuthority::RevokedSessionError)
            expect(active_token_authority_session.reload).to be_revoked_status
            expect(described_class.count).to eq(2)
          end
        end
      end

      context "without an active TokenAuthority session existing for authorization grant" do
        it "does not refresh the TokenAuthority session and raises a TokenAuthority::RevokedSessionError" do
          aggregate_failures do
            expect { method_call }.to raise_error(TokenAuthority::RevokedSessionError)
            expect(token_authority_session.reload).to be_revoked_status
            expect(described_class.count).to eq(1)
          end
        end
      end
    end

    context "when the TokenAuthority session has already been revoked" do
      let_it_be(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "revoked") }

      context "with an active TokenAuthority session existing for authorization grant" do
        it "revokes the active TokenAuthority session and raises a TokenAuthority::RevokedSessionError" do
          active_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:)
          aggregate_failures do
            expect { method_call }.to raise_error(TokenAuthority::RevokedSessionError)
            expect(active_token_authority_session.reload).to be_revoked_status
            expect(token_authority_session.reload).to be_revoked_status
            expect(described_class.count).to eq(2)
          end
        end
      end

      context "without an active TokenAuthority session existing for authorization grant" do
        it "does not refresh the TokenAuthority session and raises a TokenAuthority::RevokedSessionError" do
          aggregate_failures do
            expect { method_call }.to raise_error(TokenAuthority::RevokedSessionError)
            expect(token_authority_session.reload).to be_revoked_status
            expect(described_class.count).to eq(1)
          end
        end
      end
    end

    context "when the provided client id does not match the client id associated with the TokenAuthority session" do
      let(:client_id) { "foobar" }

      it "does not refresh the TokenAuthority session and raises a TokenAuthority::RevokedSessionError" do
        aggregate_failures do
          expect { method_call }.to raise_error(TokenAuthority::RevokedSessionError)
          expect(token_authority_session.reload).to be_revoked_status
          expect(described_class.count).to eq(1)
        end
      end
    end

    context "when the authorization grant uses a URL-based client" do
      let(:client_id_url) { "https://example.com/oauth-client" }
      let(:metadata) do
        {
          "client_id" => client_id_url,
          "client_name" => "Example Client",
          "redirect_uris" => ["https://example.com/callback"]
        }
      end
      let(:token_authority_authorization_grant) do
        create(:token_authority_authorization_grant, redeemed: true, token_authority_client: nil, client_id_url: client_id_url)
      end
      let!(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }
      let(:token_authority_refresh_token) { build(:token_authority_refresh_token, token_authority_session:) }
      let(:client_id) { client_id_url }

      before do
        allow(TokenAuthority::ClientIdResolver).to receive(:resolve)
          .with(client_id_url)
          .and_return(TokenAuthority::ClientMetadataDocument.new(metadata))
      end

      it "refreshes the TokenAuthority session using resolved_client" do
        aggregate_failures do
          expect { method_call }.to change(token_authority_session, :status).from("created").to("refreshed")
          expect(described_class.count).to eq(2)
        end
      end
    end
  end

  describe "revocation" do
    RSpec.shared_examples "a revocable TokenAuthority session" do
      let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, redeemed: true) }

      context "when the TokenAuthority session is the active TokenAuthority session" do
        let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:) }

        it "only revokes the active TokenAuthority session" do
          other_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed")
          aggregate_failures do
            expect do
              method_call
              token_authority_session.reload
            end.to change(token_authority_session, :status).from("created").to("revoked")
            expect(other_token_authority_session.reload.status).to eq("refreshed")
            expect(described_class.where(status: "revoked").count).to eq(1)
          end
        end

        it "emits session revoked event" do
          expect { method_call }
            .to emit_event("token_authority.security.session.revoked")
            .with_payload(session_id: token_authority_session.id)
        end
      end

      context "when the TokenAuthority session is not the active TokenAuthority session" do
        let(:token_authority_session) { create(:token_authority_session, token_authority_authorization_grant:, status: "refreshed") }

        it "only revokes all related TokenAuthority sessions for the authorization grant" do
          active_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:)
          alt_token_authority_session = create(
            :token_authority_session, token_authority_authorization_grant: create(:token_authority_authorization_grant, redeemed: true)
          )
          aggregate_failures do
            expect do
              method_call
              active_token_authority_session.reload
            end.to change(active_token_authority_session, :status).from("created").to("revoked")
            expect(alt_token_authority_session.reload.status).to eq("created")
            expect(described_class.where(status: "revoked").count).to eq(2)
          end
        end

        it "emits session revoked event with related session ids" do
          active_token_authority_session = create(:token_authority_session, token_authority_authorization_grant:)
          expect { method_call }
            .to emit_event("token_authority.security.session.revoked")
            .with_payload(
              session_id: token_authority_session.id,
              related_session_ids: [active_token_authority_session.id]
            )
        end
      end
    end

    describe "#revoke_self_and_active_session" do
      let(:method_call) { token_authority_session.revoke_self_and_active_session }

      it "instruments the revocation operation" do
        token_authority_session = create(:token_authority_session, token_authority_authorization_grant: create(:token_authority_authorization_grant, redeemed: true))
        expect { token_authority_session.revoke_self_and_active_session }.to instrument("token_authority.session.revoke")
      end

      it_behaves_like "a revocable TokenAuthority session"
    end

    describe ".revoke_for_token" do
      subject(:method_call) { described_class.revoke_for_token(jti:) }

      let(:jti) { token.jti }

      context "when provided an access token JTI" do
        let(:token) { build(:token_authority_access_token, token_authority_session:) }

        it_behaves_like "a revocable TokenAuthority session"
      end

      context "when provided a refresh token JTI" do
        let(:token) { build(:token_authority_refresh_token, token_authority_session:) }

        it_behaves_like "a revocable TokenAuthority session"
      end
    end

    describe ".revoke_for_access_token" do
      subject(:method_call) { described_class.revoke_for_access_token(access_token_jti:) }

      let(:access_token_jti) { token.jti }
      let(:token) { build(:token_authority_access_token, token_authority_session:) }

      it_behaves_like "a revocable TokenAuthority session"
    end

    describe ".revoke_for_refresh_token" do
      subject(:method_call) { described_class.revoke_for_refresh_token(refresh_token_jti:) }

      let(:refresh_token_jti) { token.jti }
      let(:token) { build(:token_authority_refresh_token, token_authority_session:) }

      it_behaves_like "a revocable TokenAuthority session"
    end
  end
end
