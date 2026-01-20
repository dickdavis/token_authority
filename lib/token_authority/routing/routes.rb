# frozen_string_literal: true

module ActionDispatch
  module Routing
    class Mapper
      ##
      # Adds all TokenAuthority routes including OAuth 2.0 metadata endpoints
      # (RFC 8414, RFC 9728) and mounts the TokenAuthority engine.
      #
      # Both RFC 8414 and RFC 9728 require the metadata endpoints to be at the
      # root level `/.well-known/` path, not under the engine mount path.
      #
      # @param at [String] the path where TokenAuthority engine is mounted (default: "/oauth")
      #
      # @example
      #   Rails.application.routes.draw do
      #     token_authority_routes  # Mounts at default "/oauth"
      #   end
      #
      # @example Custom mount path
      #   Rails.application.routes.draw do
      #     token_authority_routes(at: "/auth")
      #   end
      def token_authority_routes(at: "/oauth")
        # RFC 8414: Authorization Server Metadata
        get "/.well-known/oauth-authorization-server",
          to: "token_authority/metadata#show",
          defaults: {mount_path: at}

        # RFC 9728: Protected Resource Metadata
        get "/.well-known/oauth-protected-resource",
          to: "token_authority/resource_metadata#show",
          defaults: {mount_path: at}

        mount TokenAuthority::Engine => at
      end
    end
  end
end
