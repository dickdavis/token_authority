# frozen_string_literal: true

module TokenAuthority
  module Routing
    ##
    # Provides a route constraint for matching `grant_type`
    GrantTypeConstraint = Struct.new(:grant_type) do
      def matches?(request)
        request.request_parameters["grant_type"] == grant_type
      end
    end

    ##
    # Provides a route constraint for matching `token_type_hint`
    TokenTypeHintConstraint = Struct.new(:token_type_hint) do
      def matches?(request)
        request.request_parameters["token_type_hint"] == token_type_hint
      end
    end

    ##
    # Provides a route constraint for dynamic client registration (RFC 7591)
    DynamicRegistrationEnabledConstraint = Struct.new(:nothing) do
      def matches?(_request)
        TokenAuthority.config.rfc_7591_enabled
      end
    end
  end
end
