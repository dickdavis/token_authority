# frozen_string_literal: true

RSpec.shared_examples "an endpoint that requires user authentication" do
  context "with an unauthenticated user" do
    before do
      delete sign_out_path
    end

    after do
      sign_in(user)
    end

    it "redirects to the sign_in page" do
      call_endpoint
      expect(response).to redirect_to(sign_in_path)
    end
  end
end
