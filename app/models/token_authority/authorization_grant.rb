# frozen_string_literal: true

module TokenAuthority
  ##
  # Models an authorization grant.
  class AuthorizationGrant < ApplicationRecord
    include TokenAuthority::SessionCreatable

    belongs_to :user, class_name: TokenAuthority.config.user_class
    belongs_to :token_authority_client, class_name: "TokenAuthority::Client"
    has_many :token_authority_sessions,
      class_name: "TokenAuthority::Session",
      foreign_key: :token_authority_authorization_grant_id,
      inverse_of: :token_authority_authorization_grant,
      dependent: :destroy
    has_one :token_authority_challenge,
      class_name: "TokenAuthority::Challenge",
      foreign_key: :token_authority_authorization_grant_id,
      inverse_of: :token_authority_authorization_grant,
      dependent: :destroy

    accepts_nested_attributes_for :token_authority_challenge

    before_validation :generate_expires_at
    before_create :generate_public_id

    def active_token_authority_session
      token_authority_sessions.created_status.order(created_at: :desc).first
    end

    def redeem
      create_token_authority_session(grant: self) do
        update(redeemed: true)
      end
    rescue TokenAuthority::ServerError => error
      raise TokenAuthority::ServerError, error.message
    end

    private

    def generate_expires_at
      self.expires_at ||= 5.minutes.from_now
    end

    def generate_public_id
      self.public_id = SecureRandom.uuid
    end
  end
end
