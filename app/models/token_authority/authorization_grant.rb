# frozen_string_literal: true

module TokenAuthority
  # Represents an OAuth authorization grant (authorization code).
  #
  # An authorization grant is created after a user consents to allow a client
  # application access. It contains a one-time-use authorization code and PKCE
  # challenge parameters for public clients.
  #
  # The grant can be associated with either:
  # - A registered Client (stored in database)
  # - A URL-based ClientMetadataDocument (fetched via client_id_url)
  #
  # Grants have a short expiration time (5 minutes by default) and can only
  # be redeemed once. After redemption, they create a Session with access
  # and refresh tokens.
  #
  # @example Redeeming a grant
  #   session = authorization_grant.redeem(
  #     resources: ["https://api.example.com"],
  #     scopes: ["read", "write"]
  #   )
  #
  # @since 0.2.0
  class AuthorizationGrant < ApplicationRecord
    include TokenAuthority::SessionCreatable

    VALID_CODE_CHALLENGE_METHODS = %w[S256].freeze

    belongs_to :user, class_name: TokenAuthority.config.user_class
    belongs_to :token_authority_client, class_name: "TokenAuthority::Client", optional: true
    has_many :token_authority_sessions,
      class_name: "TokenAuthority::Session",
      foreign_key: :token_authority_authorization_grant_id,
      inverse_of: :token_authority_authorization_grant,
      dependent: :destroy

    validates :code_challenge_method, inclusion: {in: VALID_CODE_CHALLENGE_METHODS}, allow_nil: true
    validate :must_have_client_identifier

    before_validation :generate_expires_at
    before_create :generate_public_id

    # Returns the client associated with this grant.
    #
    # Resolves to either a registered Client or a URL-based ClientMetadataDocument
    # depending on which association is populated. URL-based clients are fetched
    # and cached on first access.
    #
    # @return [TokenAuthority::Client, TokenAuthority::ClientMetadataDocument, nil]
    #   the client object, or nil if neither association exists
    #
    # @see TokenAuthority::ClientIdResolver
    def resolved_client
      return token_authority_client if token_authority_client.present?
      return nil if client_id_url.blank?

      @resolved_client ||= TokenAuthority::ClientIdResolver.resolve(client_id_url)
    end

    # Returns the most recent active session for this grant.
    #
    # After a grant is redeemed, subsequent refresh operations create new sessions
    # with "created" status while marking old sessions as "refreshed". This method
    # returns the current active session.
    #
    # @return [TokenAuthority::Session, nil] the active session, or nil if none exists
    def active_token_authority_session
      token_authority_sessions.created_status.order(created_at: :desc).first
    end

    # Redeems the authorization code to create a new token session.
    #
    # This is the final step in the authorization code flow. The grant must not
    # have been redeemed previously, and PKCE verification (if applicable) must
    # pass before redemption succeeds.
    #
    # After successful redemption, the grant is marked as redeemed and a new
    # Session is created with access and refresh tokens.
    #
    # @param resources [Array<String>] resource indicators for the token session
    # @param scopes [Array<String>] scopes for the token session
    #
    # @return [TokenAuthority::Session] the newly created session
    #
    # @raise [TokenAuthority::ServerError] if session creation fails
    #
    # @example
    #   session = grant.redeem(
    #     resources: ["https://api.example.com"],
    #     scopes: ["read", "write"]
    #   )
    def redeem(resources: [], scopes: [])
      instrument("grant.redeem") do
        create_token_authority_session(grant: self, resources:, scopes:) do
          update(redeemed: true)
        end
      end
    rescue TokenAuthority::ServerError => error
      raise TokenAuthority::ServerError, error.message
    end

    private

    def must_have_client_identifier
      return if token_authority_client.present? || client_id_url.present?

      errors.add(:base, :must_have_client_identifier)
    end

    def generate_expires_at
      self.expires_at ||= 5.minutes.from_now
    end

    def generate_public_id
      self.public_id = SecureRandom.uuid
    end
  end
end
