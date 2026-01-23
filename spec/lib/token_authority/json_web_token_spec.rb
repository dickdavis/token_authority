# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::JsonWebToken do
  let(:secret_key) { "test_secret_key_for_jwt_encoding" }
  let(:payload) { {user_id: 123, scope: "read write"} }

  before do
    allow(TokenAuthority.config).to receive(:secret_key).and_return(secret_key)
    allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(true)
  end

  describe ".encode" do
    it "returns a JWT token string" do
      token = described_class.encode(payload)
      expect(token).to be_a(String)
      expect(token.split(".").length).to eq(3) # JWT has 3 parts
    end

    it "sets the expiration in the payload" do
      expiration = 1.hour.from_now
      token = described_class.encode(payload, expiration)
      decoded = described_class.decode(token)
      expect(decoded[:exp]).to eq(expiration.to_i)
    end

    it "instruments the encode operation" do
      expect {
        described_class.encode(payload)
      }.to instrument("token_authority.jwt.encode")
    end

    it "includes token_size in the instrumentation" do
      captured_payload = nil
      callback = ->(name, started, finished, unique_id, payload) {
        captured_payload = payload if name == "token_authority.jwt.encode"
      }

      subscriber = ActiveSupport::Notifications.subscribe("token_authority.jwt.encode", &callback)
      begin
        token = described_class.encode(payload)
        expect(captured_payload[:token_size]).to eq(token.bytesize)
      ensure
        ActiveSupport::Notifications.unsubscribe(subscriber)
      end
    end

    context "when instrumentation is disabled" do
      before do
        allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(false)
      end

      it "does not emit instrumentation events" do
        expect {
          described_class.encode(payload)
        }.not_to instrument("token_authority.jwt.encode")
      end

      it "still returns a valid token" do
        token = described_class.encode(payload)
        expect(token).to be_a(String)
      end
    end
  end

  describe ".decode" do
    let(:token) { described_class.encode(payload) }

    it "returns the decoded payload" do
      decoded = described_class.decode(token)
      expect(decoded[:user_id]).to eq(123)
      expect(decoded[:scope]).to eq("read write")
    end

    it "returns an ActiveSupport::HashWithIndifferentAccess" do
      decoded = described_class.decode(token)
      expect(decoded).to be_a(ActiveSupport::HashWithIndifferentAccess)
    end

    it "instruments the decode operation" do
      expect {
        described_class.decode(token)
      }.to instrument("token_authority.jwt.decode")
    end

    it "includes token_size in the instrumentation" do
      expect {
        described_class.decode(token)
      }.to instrument("token_authority.jwt.decode")
        .with_payload(token_size: token.bytesize)
    end

    context "when instrumentation is disabled" do
      before do
        allow(TokenAuthority.config).to receive(:instrumentation_enabled).and_return(false)
      end

      it "does not emit instrumentation events" do
        expect {
          described_class.decode(token)
        }.not_to instrument("token_authority.jwt.decode")
      end

      it "still decodes the token" do
        decoded = described_class.decode(token)
        expect(decoded[:user_id]).to eq(123)
      end
    end

    context "when decoding fails" do
      let(:invalid_token) { "invalid.jwt.token" }

      it "instruments the failure with error info" do
        expect {
          described_class.decode(invalid_token)
        }.to raise_error(JWT::DecodeError)
          .and instrument("token_authority.jwt.decode")
      end
    end
  end
end
