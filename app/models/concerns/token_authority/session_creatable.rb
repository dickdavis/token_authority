# frozen_string_literal: true

module TokenAuthority
  # Provides session creation functionality for authorization grants and token refreshes.
  #
  # This concern encapsulates the complex logic of creating a new OAuth session with
  # access and refresh token pairs. It handles:
  # - Generating access and refresh tokens with appropriate lifetimes
  # - Creating the session record with JTI references
  # - Yielding to allow the caller to update related records (e.g., marking grant as redeemed)
  # - Returning a TokenContainer with all token data
  #
  # Used by both AuthorizationGrant (when redeeming) and Session (when refreshing).
  #
  # @example In a model
  #   class AuthorizationGrant < ApplicationRecord
  #     include TokenAuthority::SessionCreatable
  #
  #     def redeem(resources: [], scopes: [])
  #       create_token_authority_session(grant: self, resources:, scopes:) do
  #         update(redeemed: true)
  #       end
  #     end
  #   end
  #
  # @since 0.2.0
  module SessionCreatable
    extend ActiveSupport::Concern
    include TokenAuthority::Instrumentation

    # Container for token response data.
    #
    # @!attribute [r] access_token
    #   The encoded JWT access token string.
    #   @return [String]
    #
    # @!attribute [r] refresh_token
    #   The encoded JWT refresh token string.
    #   @return [String]
    #
    # @!attribute [r] expiration
    #   The Unix timestamp when the access token expires.
    #   @return [Integer]
    #
    # @!attribute [r] scope
    #   Space-delimited scope string, or nil if no scopes.
    #   @return [String, nil]
    #
    # @!attribute [r] token_authority_session
    #   The created Session record.
    #   @return [TokenAuthority::Session]
    TokenContainer = Data.define(:access_token, :refresh_token, :expiration, :scope, :token_authority_session)

    private

    # Creates a new token session with access and refresh tokens.
    #
    # Generates token pairs based on the client's configured lifetimes, creates
    # a Session record, and yields to allow the caller to perform additional
    # actions (like marking a grant as redeemed).
    #
    # Emits instrumentation events for monitoring session creation performance.
    #
    # @param grant [TokenAuthority::AuthorizationGrant] the authorization grant
    # @param resources [Array<String>] resource indicators for the tokens
    # @param scopes [Array<String>] scope tokens for the tokens
    #
    # @yield allows the caller to update related records within the session creation
    #
    # @return [TokenContainer] container with access_token, refresh_token, expiration,
    #   scope, and token_authority_session
    #
    # @raise [TokenAuthority::ServerError] if session creation fails validation
    #
    # @api private
    def create_token_authority_session(grant:, resources: [], scopes: [])
      client = grant.resolved_client

      instrument("session.create") do
        access_token_expiration = client.access_token_duration.seconds.from_now.to_i
        access_token = TokenAuthority::AccessToken.default(user_id:, exp: access_token_expiration, resources:, scopes:)

        refresh_token_expiration = client.refresh_token_duration.seconds.from_now.to_i
        refresh_token = TokenAuthority::RefreshToken.default(exp: refresh_token_expiration, resources:, scopes:)

        token_authority_session = grant.token_authority_sessions.new(
          access_token_jti: access_token.jti, refresh_token_jti: refresh_token.jti
        )

        if token_authority_session.save
          yield
          scope = scopes.any? ? scopes.join(" ") : nil
          TokenContainer[access_token.to_encoded_token, refresh_token.to_encoded_token, access_token.exp, scope, token_authority_session]
        else
          errors = token_authority_session.errors.full_messages.join(", ")
          raise TokenAuthority::ServerError, I18n.t("token_authority.errors.oauth_session_failure", errors:)
        end
      end
    end
  end
end
