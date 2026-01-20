# frozen_string_literal: true

require "rails_helper"

RSpec.describe TokenAuthority::Challenge, type: :model do
  subject(:model) { build(:token_authority_challenge, token_authority_authorization_grant:) }

  let_it_be(:token_authority_client) { create(:token_authority_client) }
  let_it_be(:token_authority_authorization_grant) { create(:token_authority_authorization_grant, token_authority_client:) }

  describe "validations" do
    describe "code_challenge_method" do
      it do
        aggregate_failures do
          expect(model).to validate_inclusion_of(:code_challenge_method)
            .in_array(TokenAuthority::Challenge::VALID_CODE_CHALLENGE_METHODS)
          expect(model).to allow_value(nil).for(:code_challenge_method)
        end
      end
    end
  end

  describe "associations" do
    specify(:aggregate_failures) do
      expect(model).to belong_to(:token_authority_authorization_grant)
    end
  end
end
