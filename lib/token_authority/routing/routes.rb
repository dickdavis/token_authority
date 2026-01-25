# frozen_string_literal: true

module ActionDispatch
  module Routing
    class Mapper
      ##
      # Registers authorization server routes including OAuth endpoints and RFC 8414 metadata.
      #
      # This is the primary route helper for setting up OAuth authorization server functionality.
      # It registers two things:
      # 1. The RFC 8414 metadata endpoint at /.well-known/oauth-authorization-server
      # 2. The full TokenAuthority engine at your chosen mount path
      #
      # The metadata endpoint receives the mount path as a parameter so it can generate
      # correct URLs for the authorization and token endpoints in its response. This allows
      # clients to discover the OAuth endpoints dynamically.
      #
      # @param at [String] mount path for OAuth endpoints (default: "/oauth")
      #
      # @example Basic usage
      #   Rails.application.routes.draw do
      #     token_authority_auth_server_routes
      #     # Creates routes at /oauth/authorize, /oauth/token, etc.
      #     # Metadata at /.well-known/oauth-authorization-server
      #   end
      #
      # @example Authorization server on dedicated subdomain
      #   Rails.application.routes.draw do
      #     constraints subdomain: "auth" do
      #       token_authority_auth_server_routes
      #       # Creates https://auth.example.com/oauth/authorize, etc.
      #     end
      #   end
      #
      # @example Custom mount path
      #   token_authority_auth_server_routes(at: "/oauth2")
      #   # Creates /oauth2/authorize, /oauth2/token instead of /oauth/*
      #
      def token_authority_auth_server_routes(at: "/oauth")
        get "/.well-known/oauth-authorization-server",
          to: "token_authority/metadata#show",
          defaults: {mount_path: at}

        mount TokenAuthority::Engine => at
      end

      ##
      # Registers RFC 9728 Protected Resource Metadata endpoint for client discovery.
      #
      # Creates a route at /.well-known/oauth-protected-resource that returns metadata
      # about the protected resource, including which authorization servers can issue
      # tokens for it, what scopes are supported, and how to present bearer tokens.
      #
      # This helper is designed to be called multiple times with different subdomain
      # constraints, enabling a single Rails application to serve metadata for multiple
      # protected resources. The controller extracts the subdomain from each request and
      # looks it up as a symbol key in config.resources to find the appropriate metadata.
      #
      # For single-resource deployments, configure one entry in config.resources - it will
      # be used as the fallback for any request. For multi-resource deployments, configure
      # entries for each subdomain. The first entry in config.resources is used as the
      # fallback when no subdomain matches.
      #
      # Returns 404 if config.resources is empty.
      #
      # @example Single protected resource
      #   Rails.application.routes.draw do
      #     token_authority_auth_server_routes
      #     token_authority_protected_resource_route
      #     # Serves metadata from first entry in config.resources
      #   end
      #
      # @example Multiple protected resources at different subdomains
      #   Rails.application.routes.draw do
      #     token_authority_auth_server_routes
      #
      #     # REST API protected resource
      #     constraints subdomain: "api" do
      #       token_authority_protected_resource_route
      #       # Serves metadata from config.resources[:api]
      #     end
      #
      #     # MCP server protected resource
      #     constraints subdomain: "mcp" do
      #       token_authority_protected_resource_route
      #       # Serves metadata from config.resources[:mcp]
      #     end
      #   end
      #
      # @see https://www.rfc-editor.org/rfc/rfc9728.html RFC 9728
      def token_authority_protected_resource_route
        get "/.well-known/oauth-protected-resource",
          to: "token_authority/protected_resource_metadata#show"
      end
    end
  end
end
