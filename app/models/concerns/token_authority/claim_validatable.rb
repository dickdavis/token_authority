# frozen_string_literal: true

module TokenAuthority
  ##
  # Provides support for validating token claims
  module ClaimValidatable
    extend ActiveSupport::Concern

    REVOCABLE_CLAIMS = %i[aud iss user_id].freeze
    EXPIRABLE_CLAIMS = %i[exp].freeze

    included do
      include ActiveModel::Model
      include ActiveModel::Validations
      include ActiveModel::Validations::Callbacks

      attr_accessor :aud, :exp, :iat, :iss, :jti

      validates :jti, presence: true

      validates :aud, presence: true, format: {with: /\A#{TokenAuthority.config.audience_url}*/}

      validates :exp, presence: true
      validate do
        next if exp.blank?

        errors.add(:exp, :expired) if Time.zone.now > Time.zone.at(exp)
      end

      validates :iss, presence: true, format: {with: /\A#{TokenAuthority.config.issuer_url}\z/}

      after_validation :expire_token_authority_session, if: :errors_for_expirable_claims?
      after_validation :revoke_token_authority_session, if: :errors_for_revocable_claims?
    end

    private

    def token_authority_session
      return @token_authority_session if defined?(@token_authority_session)

      @token_authority_session = TokenAuthority::Session.find_by(query_params_for_token_authority_session)
    end

    def query_params_for_token_authority_session
      {key_for_jti_query => jti}
    end

    def key_for_jti_query
      :"#{self.class.name.demodulize.underscore}_jti"
    end

    def errors_for_revocable_claims?
      return false if skip_token_authority_session_update?

      errors.attribute_names.intersect?(REVOCABLE_CLAIMS)
    end

    def revoke_token_authority_session
      token_authority_session.update(status: "revoked")
    end

    def errors_for_expirable_claims?
      return false if skip_token_authority_session_update?

      errors.attribute_names.intersect?(EXPIRABLE_CLAIMS)
    end

    def expire_token_authority_session
      token_authority_session.update(status: "expired")
    end

    def skip_token_authority_session_update?
      errors.blank? || errors.include?(:jti)
    end
  end
end
