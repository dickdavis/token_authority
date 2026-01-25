# frozen_string_literal: true

TokenAuthority.configure do |config|
  # ==========================================================================
  # General
  # ==========================================================================

  # The secret key used for signing JWT tokens and generating client secrets.
  # This should be a secure, random string. By default, it uses the application's
  # secret_key_base from credentials or configuration.
  config.secret_key = Rails.application.credentials.secret_key_base || Rails.application.secret_key_base

  # Enable event logging (default: true).
  # config.event_logging_enabled = true

  # Enable debug events (default: false).
  # config.event_logging_debug_events = false

  # Enable ActiveSupport::Notifications instrumentation (default: true).
  # config.instrumentation_enabled = true

  # ==========================================================================
  # User Authentication
  # ==========================================================================

  # The authenticatable controller for the authorization grants controller (consent screen).
  # Default: "ApplicationController"
  # config.authenticatable_controller = "ApplicationController"

  # The class name of your user model.
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
  # Scopes
  # ==========================================================================

  # Configure allowed scopes with human-friendly display names.
  config.scopes = {
    "read" => "Read your data",
    "write" => "Create and modify your data",
    "delete" => "Delete your data",
    "profile" => "View your profile information"
  }

  # Require the scope parameter in authorization requests.
  # config.require_scope = false

  # ==========================================================================
  # Resources (RFC 9728 / RFC 8707)
  # ==========================================================================

  # Protected resources keyed by subdomain. For single-resource deployments,
  # just configure one entry - it will be used for all requests.
  # For multi-resource deployments, add entries for each subdomain.
  # The first entry is used as the default when no subdomain matches.
  #
  # Each entry must include the :resource field (required per RFC 9728).
  # All other fields are optional.
  config.resources = {
    api: {
      resource: "http://localhost:3000/api/",  # Required
      resource_name: "Demo API",
      scopes_supported: %w[read write delete profile]
    }
  }

  # Example multi-resource configuration:
  # config.resources = {
  #   api: {
  #     resource: "https://api.example.com",
  #     resource_name: "REST API",
  #     scopes_supported: %w[read write]
  #   },
  #   mcp: {
  #     resource: "https://mcp.example.com",
  #     resource_name: "MCP Server",
  #     scopes_supported: %w[mcp:tools mcp:resources]
  #   }
  # }

  # Require the resource parameter in authorization requests.
  # config.require_resource = false

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
  # config.rfc_9068_default_access_token_duration = 300

  # Default duration for refresh tokens in seconds (14 days).
  # config.rfc_9068_default_refresh_token_duration = 1_209_600

  # ==========================================================================
  # Server Metadata (RFC 8414)
  # ==========================================================================

  # URL to developer documentation for your OAuth server.
  # config.rfc_8414_service_documentation = "https://example.com/docs/oauth"

  # ==========================================================================
  # Dynamic Client Registration (RFC 7591)
  # ==========================================================================

  # Enable dynamic client registration endpoint (/register).
  # config.rfc_7591_enabled = false

  # Require an initial access token for client registration.
  # config.rfc_7591_require_initial_access_token = false

  # Validator proc for initial access tokens.
  # config.rfc_7591_initial_access_token_validator = ->(token) {
  #   token == ENV["REGISTRATION_ACCESS_TOKEN"]
  # }

  # Allowed grant types for dynamically registered clients.
  # config.rfc_7591_allowed_grant_types = %w[authorization_code refresh_token]

  # Allowed response types for dynamically registered clients.
  # config.rfc_7591_allowed_response_types = %w[code]

  # Allowed token endpoint authentication methods.
  # config.rfc_7591_allowed_token_endpoint_auth_methods = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt]

  # Client secret expiration duration in seconds (nil = never expires).
  # config.rfc_7591_client_secret_expiration = nil

  # JWKS for verifying software statements.
  # config.rfc_7591_software_statement_jwks = nil

  # Require software statements for client registration.
  # config.rfc_7591_software_statement_required = false

  # Cache TTL in seconds for fetched JWKS from jwks_uri (default: 1 hour).
  # config.rfc_7591_jwks_cache_ttl = 3600

  # ==========================================================================
  # Client Metadata Document (draft-ietf-oauth-client-id-metadata-document)
  # ==========================================================================

  # Enable URL-based client identifiers (default: true).
  # config.client_metadata_document_enabled = true

  # Allowed hosts for client metadata document URLs (default: nil = all hosts).
  # config.client_metadata_document_allowed_hosts = nil

  # Blocked hosts for client metadata document URLs (default: []).
  # config.client_metadata_document_blocked_hosts = []

  # Cache TTL in seconds for fetched metadata documents (default: 1 hour).
  # config.client_metadata_document_cache_ttl = 3600

  # Maximum response size in bytes (default: 5KB).
  # config.client_metadata_document_max_response_size = 5120

  # Connection and read timeouts in seconds (default: 5 each).
  # config.client_metadata_document_connect_timeout = 5
  # config.client_metadata_document_read_timeout = 5
end
