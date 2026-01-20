# frozen_string_literal: true

module ActionDispatch
  module Routing
    class Mapper
      ##
      # Adds the RFC 8414 OAuth 2.0 Authorization Server Metadata route.
      #
      # RFC 8414 requires the metadata endpoint to be at the root level
      # `/.well-known/oauth-authorization-server` path, not under the engine mount path.
      #
      # @param mount_path [String] the path where TokenAuthority engine is mounted (default: "/oauth")
      #
      # @example
      #   Rails.application.routes.draw do
      #     token_authority_metadata_routes  # Uses default mount_path "/oauth"
      #     mount TokenAuthority::Engine => "/oauth"
      #   end
      #
      # @example Custom mount path
      #   Rails.application.routes.draw do
      #     token_authority_metadata_routes(mount_path: "/auth")
      #     mount TokenAuthority::Engine => "/auth"
      #   end
      def token_authority_metadata_routes(mount_path: "/oauth")
        get "/.well-known/oauth-authorization-server",
          to: "token_authority/metadata#show",
          defaults: {mount_path: mount_path}
      end
    end
  end
end
