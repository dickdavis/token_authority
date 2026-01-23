# frozen_string_literal: true

RSpec.shared_examples "a model that creates TokenAuthority sessions" do
  context "when the token authority session is created" do
    it "creates a TokenAuthority::Session record" do
      expect { method_call }.to change(TokenAuthority::Session, :count).by(1)
    end

    it "returns a valid access token" do
      results = method_call
      expect(results.access_token).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
    end

    it "returns an access token with valid aud, exp, iat, iss, jti, and user_id claims" do
      token = TokenAuthority::JsonWebToken.decode(method_call.access_token)
      aggregate_failures do
        expect(token[:aud]).to eq(TokenAuthority.config.rfc_9068_audience_url)
        expect(token[:exp]).to be_a(Integer)
        expect(token[:iat]).to be_a(Integer)
        expect(token[:iss]).to eq(TokenAuthority.config.rfc_9068_issuer_url)
        expect(token[:jti]).to match(TokenAuthority::Session::VALID_UUID_REGEX)
        expect(token[:user_id]).to eq(token_authority_authorization_grant.user_id)
      end
    end

    it "saves the access_token_jti in the TokenAuthority::Session" do
      results = method_call
      token = TokenAuthority::JsonWebToken.decode(results.access_token)
      expect(token_authority_authorization_grant.active_token_authority_session.access_token_jti).to eq(token[:jti])
    end

    it "returns a valid refresh token" do
      results = method_call
      expect(results.refresh_token).to match(/\A[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\z/)
    end

    it "returns a refresh token with valid aud, exp, iat, iss, jti, and user_id claims" do
      token = TokenAuthority::JsonWebToken.decode(method_call.refresh_token)
      aggregate_failures do
        expect(token[:aud]).to eq(TokenAuthority.config.rfc_9068_audience_url)
        expect(token[:exp]).to be_a(Integer)
        expect(token[:iat]).to be_a(Integer)
        expect(token[:iss]).to eq(TokenAuthority.config.rfc_9068_issuer_url)
        expect(token[:jti]).to match(TokenAuthority::Session::VALID_UUID_REGEX)
      end
    end

    it "saves the refresh_token_jti in the TokenAuthority::Session" do
      results = method_call
      token = TokenAuthority::JsonWebToken.decode(results.refresh_token)
      expect(token_authority_authorization_grant.active_token_authority_session.refresh_token_jti).to eq(token[:jti])
    end

    it "returns the access token expiration" do
      Timecop.freeze(Time.zone.now) do
        results = method_call
        token = TokenAuthority::JsonWebToken.decode(results.access_token)
        expect(token[:exp]).to eq(results.expiration)
      end
    end
  end

  context "when the token authority session fails to create" do
    let(:token_authority_session_double) { build(:token_authority_session, token_authority_authorization_grant:, access_token_jti: nil) }

    before do
      allow(TokenAuthority::Session).to receive(:new).and_return(token_authority_session_double)
    end

    it "raises a TokenAuthority::ServerError" do
      expect { method_call }.to raise_error(
        TokenAuthority::ServerError,
        "Failed to create OAuthSession. Errors: Access token JTI can't be blank, Access token JTI is invalid"
      )
    end
  end
end

RSpec.shared_examples "a model that creates TokenAuthority sessions with RFC 8707 resources" do
  context "when resources are provided (RFC 8707)" do
    context "with a single resource" do
      let(:resources) { ["https://api.example.com"] }

      it "sets the access token aud claim to the single resource" do
        results = method_call_with_resources
        token = TokenAuthority::JsonWebToken.decode(results.access_token)
        expect(token[:aud]).to eq("https://api.example.com")
      end

      it "sets the refresh token aud claim to the single resource" do
        results = method_call_with_resources
        token = TokenAuthority::JsonWebToken.decode(results.refresh_token)
        expect(token[:aud]).to eq("https://api.example.com")
      end
    end

    context "with multiple resources" do
      let(:resources) { ["https://api1.example.com", "https://api2.example.com"] }

      it "sets the access token aud claim to the array of resources" do
        results = method_call_with_resources
        token = TokenAuthority::JsonWebToken.decode(results.access_token)
        expect(token[:aud]).to match_array(resources)
      end

      it "sets the refresh token aud claim to the array of resources" do
        results = method_call_with_resources
        token = TokenAuthority::JsonWebToken.decode(results.refresh_token)
        expect(token[:aud]).to match_array(resources)
      end
    end
  end
end
