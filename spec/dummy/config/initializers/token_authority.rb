# frozen_string_literal: true

TokenAuthority.configure do |config|
  # ==========================================================================
  # JWT Configuration
  # ==========================================================================

  # The audience URL for JWT tokens. This is typically your API's base URL.
  # Used as the "aud" (audience) claim in issued tokens.
  config.audience_url = ENV.fetch("TOKEN_AUTHORITY_AUDIENCE_URL", "http://localhost:3000/api/")

  # The issuer URL for JWT tokens. This is typically your application's base URL.
  # Used as the "iss" (issuer) claim in issued tokens.
  config.issuer_url = ENV.fetch("TOKEN_AUTHORITY_ISSUER_URL", "http://localhost:3000/")

  # The secret key used for signing JWT tokens and generating client secrets.
  # This should be a secure, random string. By default, it uses the application's
  # secret_key_base from credentials or configuration.
  config.secret_key = Rails.application.credentials.secret_key_base || Rails.application.secret_key_base

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
end
