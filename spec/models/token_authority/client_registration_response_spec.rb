# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::ClientRegistrationResponse, type: :model do
  subject(:response) { described_class.new(client: client) }

  describe "#to_h" do
    context "with a confidential client" do
      let(:client) { create(:token_authority_client, client_type: "confidential", name: "Test Client") }

      it "includes client_id" do
        expect(response.to_h[:client_id]).to eq(client.public_id)
      end

      it "includes client_secret" do
        expect(response.to_h[:client_secret]).to eq(client.client_secret)
      end

      it "includes client_id_issued_at as Unix timestamp" do
        expect(response.to_h[:client_id_issued_at]).to eq(client.client_id_issued_at.to_i)
      end

      it "includes client_secret_expires_at" do
        expect(response.to_h[:client_secret_expires_at]).to eq(0)
      end

      it "includes redirect_uris" do
        expect(response.to_h[:redirect_uris]).to eq(client.redirect_uris)
      end

      it "includes client_name" do
        expect(response.to_h[:client_name]).to eq("Test Client")
      end

      it "includes token_endpoint_auth_method" do
        expect(response.to_h[:token_endpoint_auth_method]).to eq(client.token_endpoint_auth_method)
      end
    end

    context "with a public client" do
      let(:client) { create(:token_authority_client, client_type: "public", name: "Public Client") }

      it "includes client_id" do
        expect(response.to_h[:client_id]).to eq(client.public_id)
      end

      it "does not include client_secret" do
        expect(response.to_h).not_to have_key(:client_secret)
      end

      it "does not include client_secret_expires_at" do
        expect(response.to_h).not_to have_key(:client_secret_expires_at)
      end
    end
  end
end
