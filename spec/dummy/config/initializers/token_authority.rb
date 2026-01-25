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

  # Require the scope parameter in authorization requests (default: true).
  # Set to false for backwards compatibility with existing tests.
  config.require_scope = false

  # ==========================================================================
  # Resources (RFC 9728 / RFC 8707)
  # ==========================================================================

  # Protected resources keyed by identifier. For single-resource deployments,
  # just configure one entry - it will be used for all requests.
  # For multi-resource deployments, add entries for each subdomain.
  # The first entry is used as the default when no subdomain matches.
  #
  # Each entry must include the :resource field (required per RFC 9728).
  # The :resource URL is used as the audience (aud) claim in access tokens.
  # The first :authorization_servers entry is used as the issuer (iss) claim.
  config.resources = {
    api: {
      resource: "http://localhost:3000/api/",
      resource_name: "Demo API",
      scopes_supported: %w[read write delete profile],
      authorization_servers: ["http://localhost:3000/"],
      bearer_methods_supported: ["header"],
      resource_documentation: "http://localhost:3000/docs/api"
    }
  }

  # Require the resource parameter in authorization requests (default: true).
  # Set to false for backwards compatibility with existing tests.
  config.require_resource = false

  # ==========================================================================
  # JWT Access Tokens (RFC 9068)
  # ==========================================================================

  # The audience URL for JWT tokens (default: nil).
  # When nil (recommended), the audience is the resource URL from config.resources.
  # config.token_audience_url = nil

  # The issuer URL for JWT tokens (default: nil).
  # When nil, the issuer is derived from the first resource's :authorization_servers.
  # config.token_issuer_url = nil

  # Default duration for access tokens in seconds (5 minutes).
  # config.default_access_token_duration = 300

  # Default duration for refresh tokens in seconds (14 days).
  # config.default_refresh_token_duration = 1_209_600

  # ==========================================================================
  # Server Metadata (RFC 8414)
  # ==========================================================================

  # URL to developer documentation for your OAuth server.
  # config.authorization_server_documentation = "https://example.com/docs/oauth"

  # ==========================================================================
  # Dynamic Client Registration (RFC 7591)
  # ==========================================================================

  # Enable dynamic client registration endpoint (/register) (default: true).
  # config.dcr_enabled = true

  # Require an initial access token for client registration.
  # config.dcr_require_initial_access_token = false

  # Validator proc for initial access tokens.
  # config.dcr_initial_access_token_validator = ->(token) {
  #   token == ENV["REGISTRATION_ACCESS_TOKEN"]
  # }

  # Allowed grant types for dynamically registered clients.
  # config.dcr_allowed_grant_types = %w[authorization_code refresh_token]

  # Allowed response types for dynamically registered clients.
  # config.dcr_allowed_response_types = %w[code]

  # Allowed token endpoint authentication methods.
  # config.dcr_allowed_token_endpoint_auth_methods = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt]

  # Client secret expiration duration in seconds (nil = never expires).
  # config.dcr_client_secret_expiration = nil

  # JWKS for verifying software statements.
  # config.dcr_software_statement_jwks = nil

  # Require software statements for client registration.
  # config.dcr_software_statement_required = false

  # Cache TTL in seconds for fetched JWKS from jwks_uri (default: 1 hour).
  # config.dcr_jwks_cache_ttl = 3600

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
