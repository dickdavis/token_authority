# frozen_string_literal: true

module TokenAuthority
  # Provides routing utilities for the TokenAuthority engine.
  #
  # @since 0.2.0
  module Routing
    # Route constraint for matching the grant_type parameter in token requests.
    #
    # This allows routing different grant types (authorization_code, refresh_token)
    # to different controller actions based on the request parameters.
    #
    # @example In routes.rb
    #   post "token",
    #     to: "sessions#create_from_authorization_code",
    #     constraints: GrantTypeConstraint.new("authorization_code")
    #
    # @since 0.2.0
    GrantTypeConstraint = Struct.new(:grant_type) do
      # Determines if the request's grant_type parameter matches the constraint.
      #
      # @param request [ActionDispatch::Request] the Rails request object
      # @return [Boolean] true if the grant_type parameter matches
      def matches?(request)
        request.request_parameters["grant_type"] == grant_type
      end
    end

    # Route constraint for matching the token_type_hint parameter in revocation requests.
    #
    # This allows routing access token and refresh token revocations to different
    # controller actions for optimized lookups.
    #
    # @example In routes.rb
    #   post "revoke",
    #     to: "sessions#revoke_access_token",
    #     constraints: TokenTypeHintConstraint.new("access_token")
    #
    # @since 0.2.0
    TokenTypeHintConstraint = Struct.new(:token_type_hint) do
      # Determines if the request's token_type_hint parameter matches the constraint.
      #
      # @param request [ActionDispatch::Request] the Rails request object
      # @return [Boolean] true if the token_type_hint parameter matches
      def matches?(request)
        request.request_parameters["token_type_hint"] == token_type_hint
      end
    end

    # Route constraint that checks if dynamic client registration (RFC 7591) is enabled.
    #
    # This prevents registration endpoints from being accessible when the feature
    # is disabled in configuration.
    #
    # @example In routes.rb
    #   post "clients",
    #     to: "clients#create",
    #     constraints: DynamicRegistrationEnabledConstraint.new
    #
    # @since 0.2.0
    DynamicRegistrationEnabledConstraint = Struct.new(:nothing) do
      # Determines if dynamic client registration is enabled in the configuration.
      #
      # @param _request [ActionDispatch::Request] the Rails request object (unused)
      # @return [Boolean] true if dynamic client registration is enabled
      def matches?(_request)
        TokenAuthority.config.dcr_enabled
      end
    end
  end
end
