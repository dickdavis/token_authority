# frozen_string_literal: true

module ActionDispatch
  module Routing
    class Mapper
      ##
      # Adds OAuth 2.0 metadata routes for both Authorization Server (RFC 8414)
      # and Protected Resource (RFC 9728).
      #
      # Both RFCs require the metadata endpoints to be at the root level
      # `/.well-known/` path, not under the engine mount path.
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
        # RFC 8414: Authorization Server Metadata
        get "/.well-known/oauth-authorization-server",
          to: "token_authority/metadata#show",
          defaults: {mount_path: mount_path}

        # RFC 9728: Protected Resource Metadata
        get "/.well-known/oauth-protected-resource",
          to: "token_authority/resource_metadata#show",
          defaults: {mount_path: mount_path}
      end
    end
  end
end
