# frozen_string_literal: true

module TokenAuthority
  ##
  # Models a challenge used in PKCE
  class Challenge < ApplicationRecord
    VALID_CODE_CHALLENGE_METHODS = %w[S256].freeze

    belongs_to :token_authority_authorization_grant, class_name: "TokenAuthority::AuthorizationGrant"

    validates :code_challenge_method, allow_blank: true, inclusion: {in: VALID_CODE_CHALLENGE_METHODS}
  end
end
