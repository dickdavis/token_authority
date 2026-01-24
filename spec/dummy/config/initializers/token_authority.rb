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
  # JWT Access Tokens (RFC 9068)
  # ==========================================================================

  # The audience URL for JWT tokens. This is typically your API's base URL.
  # Used as the "aud" (audience) claim in issued tokens.
  config.rfc_9068_audience_url = ENV.fetch("TOKEN_AUTHORITY_AUDIENCE_URL", "http://localhost:3000/api/")

  # The issuer URL for JWT tokens. This is typically your application's base URL.
  # Used as the "iss" (issuer) claim in issued tokens.
  config.rfc_9068_issuer_url = ENV.fetch("TOKEN_AUTHORITY_ISSUER_URL", "http://localhost:3000/")

  # Default duration for access tokens in seconds (5 minutes).
  # This value is used when creating new clients without explicit durations.
  # config.rfc_9068_default_access_token_duration = 300

  # Default duration for refresh tokens in seconds (14 days).
  # This value is used when creating new clients without explicit durations.
  # config.rfc_9068_default_refresh_token_duration = 1_209_600

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
  # Default: "ApplicationController"
  # config.authenticatable_controller = "ApplicationController"

  # The class name of your user model. This is used for the belongs_to association
  # in TokenAuthority::AuthorizationGrant.
  # Default: "User"
  # config.user_class = "User"

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

  # URL to developer documentation for your OAuth server.
  # Included in the /.well-known/oauth-authorization-server response.
  # config.rfc_8414_service_documentation = "https://example.com/docs/oauth"

  # Note: scopes_supported in the metadata response is automatically derived
  # from the keys of config.scopes (see Scopes section below).

  # ==========================================================================
  # Protected Resource Metadata (RFC 9728)
  # ==========================================================================

  # Protected resource configuration for requests without a subdomain.
  # This is the default configuration used when no subdomain-specific config is found.
  config.protected_resource = {
    resource: "http://localhost:3000/api/",
    resource_name: "Demo API",
    scopes_supported: %w[read write delete profile]
  }

  # Protected resource configuration keyed by subdomain.
  # Use this to serve different metadata based on the request subdomain.
  # config.protected_resources = {
  #   "api" => {
  #     resource: "https://api.example.com",
  #     resource_name: "REST API",
  #     scopes_supported: %w[read write],
  #     bearer_methods_supported: %w[header]
  #   },
  #   "mcp" => {
  #     resource: "https://mcp.example.com",
  #     resource_name: "MCP Server",
  #     scopes_supported: %w[mcp:tools mcp:resources],
  #     bearer_methods_supported: %w[header]
  #   }
  # }

  # ==========================================================================
  # Scopes
  # ==========================================================================

  # Configure allowed scopes with human-friendly display names.
  # Keys are the scope strings (used as the allowlist), values are display names
  # shown on the consent screen.
  #
  # Set to nil or {} to disable scope validation entirely.
  # When configured, only these scopes are allowed in authorization requests.
  config.scopes = {
    "read" => "Read your data",
    "write" => "Create and modify your data",
    "delete" => "Delete your data",
    "profile" => "View your profile information"
  }

  # Require the scope parameter in authorization requests.
  # When true, clients must specify at least one scope.
  # config.require_scope = false

  # ==========================================================================
  # Resource Indicators (RFC 8707)
  # ==========================================================================

  # Configure allowed resources with human-friendly display names.
  # Keys are the resource URIs (used as the allowlist), values are display names
  # shown on the consent screen.
  #
  # Set to nil or {} to disable resource indicators entirely.
  # When configured, only these resources are allowed in authorization requests.
  config.rfc_8707_resources = {
    "http://localhost:3000/api/" => "Demo API"
  }

  # Require the resource parameter in authorization requests.
  # When true, clients must specify at least one resource.
  # config.rfc_8707_require_resource = false

  # ==========================================================================
  # Dynamic Client Registration (RFC 7591)
  # ==========================================================================

  # Enable dynamic client registration endpoint (/register).
  # When enabled, clients can register programmatically via POST requests.
  # Disabled by default for security - enable only if you need this feature.
  # config.rfc_7591_enabled = false

  # Require an initial access token for client registration.
  # When enabled, registration requests must include a Bearer token.
  # config.rfc_7591_require_initial_access_token = false

  # Validator proc for initial access tokens.
  # Must return true if the token is valid, false otherwise.
  # Example:
  # config.rfc_7591_initial_access_token_validator = ->(token) {
  #   token == ENV["REGISTRATION_ACCESS_TOKEN"]
  # }

  # Allowed grant types for dynamically registered clients.
  # config.rfc_7591_allowed_grant_types = %w[authorization_code refresh_token]

  # Allowed response types for dynamically registered clients.
  # config.rfc_7591_allowed_response_types = %w[code]

  # Allowed token endpoint authentication methods.
  # Options: none, client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt
  # config.rfc_7591_allowed_token_endpoint_auth_methods = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt]

  # Client secret expiration duration in seconds (nil = never expires).
  # config.rfc_7591_client_secret_expiration = nil

  # JWKS for verifying software statements (signed JWTs with client metadata).
  # Set to a JWKS hash to enable software statement verification.
  # config.rfc_7591_software_statement_jwks = nil

  # Require software statements for client registration.
  # When enabled, registration requests must include a valid software_statement.
  # config.rfc_7591_software_statement_required = false

  # Cache TTL in seconds for fetched JWKS from jwks_uri (default: 1 hour).
  # config.rfc_7591_jwks_cache_ttl = 3600

  # ==========================================================================
  # Client Metadata Document (draft-ietf-oauth-client-id-metadata-document)
  # ==========================================================================

  # URL-based client identifiers allow clients to use HTTPS URLs as their client_id.
  # The authorization server fetches client metadata from the URL at runtime.
  # This enables lightweight, decentralized client registration.
  #
  # SECURITY CONSIDERATION: By default, any HTTPS URL can be used as a client_id,
  # meaning any server on the internet can act as an OAuth client to your
  # authorization server. This is appropriate for MCP servers and open ecosystems.
  # For restricted access, configure allowed_hosts to limit which domains can
  # host client metadata documents.
  #
  # Example for production with restricted access:
  #   config.client_metadata_document_allowed_hosts = ["trusted-partner.com", "*.mycompany.com"]

  # Enable URL-based client identifiers (default: true).
  # config.client_metadata_document_enabled = true

  # Allowed hosts for client metadata document URLs (default: nil = all hosts).
  # config.client_metadata_document_allowed_hosts = nil

  # Blocked hosts for client metadata document URLs (default: []).
  # Example: ["internal.example.com", "*.local"]
  # config.client_metadata_document_blocked_hosts = []

  # Cache TTL in seconds for fetched metadata documents (default: 1 hour).
  # config.client_metadata_document_cache_ttl = 3600

  # Maximum response size in bytes (default: 5KB).
  # config.client_metadata_document_max_response_size = 5120

  # Connection and read timeouts in seconds (default: 5 each).
  # config.client_metadata_document_connect_timeout = 5
  # config.client_metadata_document_read_timeout = 5
end
