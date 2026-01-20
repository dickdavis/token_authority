# frozen_string_literal: true

TokenAuthority.configure do |config|
  # ==========================================================================
  # General
  # ==========================================================================

  # The secret key used for signing JWT tokens and generating client secrets.
  # This should be a secure, random string. By default, it uses the application's
  # secret_key_base from credentials or configuration.
  config.secret_key = Rails.application.credentials.secret_key_base || Rails.application.secret_key_base

  # ==========================================================================
  # Token
  # ==========================================================================

  # The audience URL for JWT tokens. This is typically your API's base URL.
  # Used as the "aud" (audience) claim in issued tokens.
  config.audience_url = ENV.fetch("TOKEN_AUTHORITY_AUDIENCE_URL", "http://localhost:3000/api/")

  # The issuer URL for JWT tokens. This is typically your application's base URL.
  # Used as the "iss" (issuer) claim in issued tokens.
  config.issuer_url = ENV.fetch("TOKEN_AUTHORITY_ISSUER_URL", "http://localhost:3000/")

  # Default duration for access tokens in seconds (5 minutes).
  # This value is used when creating new clients without explicit durations.
  # config.default_access_token_duration = 300

  # Default duration for refresh tokens in seconds (14 days).
  # This value is used when creating new clients without explicit durations.
  # config.default_refresh_token_duration = 1_209_600

  # ==========================================================================
  # User Authentication
  # ==========================================================================

  # The authenticatable controller for the authorization grants controller (consent screen).
  # This controller must implement:
  # - authenticate_user! (before_action that ensures user is logged in)
  # - current_user (returns the currently authenticated user)
  #
  # For Devise users, ApplicationController already has these methods.
  # For other authentication systems, either:
  # 1. Implement these methods on ApplicationController, or
  # 2. Set this to a controller that provides these methods
  config.authenticatable_controller = "ApplicationController"

  # The class name of your user model. This is used for the belongs_to association
  # in TokenAuthority::AuthorizationGrant.
  config.user_class = "User"

  # ==========================================================================
  # UI/Layout
  # ==========================================================================

  # The layout used for the OAuth consent screen.
  config.consent_page_layout = "application"

  # The layout used for error pages (e.g., invalid redirect URL).
  config.error_page_layout = "application"

  # ==========================================================================
  # Server Metadata (RFC 8414)
  # ==========================================================================

  # OAuth scopes supported by your authorization server.
  # Included in the /.well-known/oauth-authorization-server response.
  # config.scopes_supported = ["read", "write"]

  # URL to developer documentation for your OAuth server.
  # Included in the /.well-known/oauth-authorization-server response.
  # config.service_documentation = "https://example.com/docs/oauth"

  # ==========================================================================
  # Protected Resource Metadata (RFC 9728)
  # ==========================================================================

  # The protected resource's identifier URL.
  # Defaults to issuer_url if not set.
  # config.resource_url = "https://api.example.com/"

  # Scopes accepted by the protected resource.
  # Falls back to scopes_supported if not set.
  # config.resource_scopes_supported = ["api:read", "api:write"]

  # List of authorization server issuer URLs that can issue tokens for this resource.
  # Defaults to the local authorization server (issuer_url) if not set.
  # config.resource_authorization_servers = ["https://auth.example.com"]

  # Token presentation methods supported by the resource (e.g., "header", "body", "query").
  # config.resource_bearer_methods_supported = ["header"]

  # URL to the resource's JSON Web Key Set (JWKS).
  # config.resource_jwks_uri = "https://api.example.com/.well-known/jwks.json"

  # Human-readable name for the protected resource.
  # config.resource_name = "Example API"

  # URL to developer documentation for the protected resource.
  # config.resource_documentation = "https://example.com/docs/api"

  # URL to the resource's privacy policy.
  # config.resource_policy_uri = "https://example.com/privacy"

  # URL to the resource's terms of service.
  # config.resource_tos_uri = "https://example.com/tos"
end
