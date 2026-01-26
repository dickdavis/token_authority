# frozen_string_literal: true

RSpec.shared_context "with an authenticated client" do |method, path|
  subject(:call_endpoint) { send(method, url, **options_for_request) }

  let(:url) { send(path) }
  let(:options_for_request) { {params: shared_context_params, headers: shared_context_headers} }
  let(:shared_context_params) { (try(:params) || {}).reverse_merge!(client_id: token_authority_client.public_id) }
  let(:shared_context_headers) { (try(:headers) || {}).reverse_merge!(http_basic_auth_header) }
  let(:http_basic_auth_header) do
    auth = ActionController::HttpAuthentication::Basic.encode_credentials(token_authority_client.public_id, token_authority_client.client_secret)
    {"HTTP_AUTHORIZATION" => auth}
  end
end

RSpec.shared_context "with client_secret_post authentication" do |method, path|
  subject(:call_endpoint) { send(method, url, **options_for_request) }

  let(:url) { send(path) }
  let(:options_for_request) { {params: shared_context_params} }
  let(:shared_context_params) do
    (try(:params) || {}).reverse_merge!(
      client_id: token_authority_client.public_id,
      client_secret: token_authority_client.client_secret
    )
  end
end

RSpec.shared_examples "an endpoint that requires client authentication" do
  shared_examples "returns HTTP status unauthorized and access denied message" do
    it "returns HTTP status unauthorized and access denied message" do
      call_endpoint
      aggregate_failures do
        expect(response).to have_http_status(:unauthorized)
        expect(response.body.chomp).to eq("HTTP Basic: Access denied.")
      end
    end
  end

  context "with client_id param that does not match client id in header" do
    let(:shared_context_params) { super().merge(client_id: "negativetestclient") }

    include_examples "returns HTTP status unauthorized and access denied message"
  end

  context "without HTTP basic auth header" do
    let(:http_basic_auth_header) { {} }

    include_examples "returns HTTP status unauthorized and access denied message"
  end
end

RSpec.shared_examples "an endpoint that supports client_secret_post authentication" do
  context "with valid client_secret in POST body (no HTTP Basic header)" do
    let(:http_basic_auth_header) { {} }
    let(:shared_context_params) do
      super().merge(client_secret: token_authority_client.client_secret)
    end

    it "authenticates successfully" do
      call_endpoint
      expect(response).not_to have_http_status(:unauthorized)
    end
  end

  context "with invalid client_secret in POST body" do
    let(:http_basic_auth_header) { {} }
    let(:shared_context_params) do
      super().merge(client_secret: "invalid_secret")
    end

    it "returns HTTP status unauthorized" do
      call_endpoint
      expect(response).to have_http_status(:unauthorized)
    end
  end
end
