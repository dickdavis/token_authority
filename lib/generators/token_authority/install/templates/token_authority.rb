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
  # When enabled, events are emitted and logged to Rails.logger.
  # Events include: authorization requests, consent actions, token exchanges,
  # token refreshes, revocations, client authentication, and security events.
  # config.event_logging_enabled = true

  # Enable debug events (default: false).
  # Debug events provide detailed information useful during development,
  # such as PKCE validation steps and cache hits/misses.
  # config.event_logging_debug_events = false

  # Enable ActiveSupport::Notifications instrumentation (default: true).
  # config.instrumentation_enabled = true

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
  # Scopes
  # ==========================================================================

  # Configure allowed scopes with human-friendly display names.
  # Keys are the scope strings (used as the allowlist), values are display names
  # shown on the consent screen.
  #
  # IMPORTANT: You must configure at least one scope since require_scope is true by default.
  config.scopes = {
    "read" => "Read access to your data",
    "write" => "Write access to your data"
  }

  # Require the scope parameter in authorization requests (default: true).
  # When true, clients must specify at least one scope.
  # config.require_scope = true

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
  #
  # Resource indicators (RFC 8707) are automatically enabled when resources are
  # configured. The allowlist of valid resource URIs is derived from the :resource
  # key in the configuration below.
  #
  # IMPORTANT: You must configure at least one resource since require_resource is true by default.
  #
  # Available options:
  #   resource (required)        - The protected resource URI (used as aud claim)
  #   resource_name              - Human-readable name shown on consent screen
  #   scopes_supported           - Array of scopes this resource accepts
  #   authorization_servers      - Array of auth server URLs (first used as iss claim)
  #   bearer_methods_supported   - Array of supported bearer token methods
  #   jwks_uri                   - URI for JSON Web Key Set endpoint
  #   resource_documentation     - URL for API documentation
  #   resource_policy_uri        - URL for privacy policy
  #   resource_tos_uri           - URL for terms of service
  config.resources = {
    api: {
      resource: ENV.fetch("TOKEN_AUTHORITY_RESOURCE_URL", "http://localhost:3000/api"),
      resource_name: "My API",
      scopes_supported: %w[read write],
      authorization_servers: [ENV.fetch("TOKEN_AUTHORITY_BASE_URL", "http://localhost:3000")],
      bearer_methods_supported: ["header"],
      resource_documentation: "http://localhost:3000/docs/api"
    }
  }

  # Require the resource parameter in authorization requests (default: true).
  # When true, clients must specify at least one resource.
  # config.require_resource = true

  # ==========================================================================
  # JWT Access Tokens (RFC 9068)
  # ==========================================================================

  # The issuer URL for JWT tokens (default: nil).
  # Used as the "iss" (issuer) claim in issued tokens.
  # If nil, the issuer is derived from the first resource's :authorization_servers.
  # You must configure either this OR :authorization_servers on at least one resource.
  # config.token_issuer_url = nil

  # The audience URL for JWT tokens (default: nil).
  # When set, this value is used as the "aud" claim for all tokens.
  # When nil (recommended), the audience is the resource URL from config.resources.
  # config.token_audience_url = nil

  # Default duration for access tokens in seconds (5 minutes).
  # This value is used when creating new clients without explicit durations.
  # config.default_access_token_duration = 300

  # Default duration for refresh tokens in seconds (14 days).
  # This value is used when creating new clients without explicit durations.
  # config.default_refresh_token_duration = 1_209_600

  # ==========================================================================
  # Server Metadata (RFC 8414)
  # ==========================================================================

  # URL to developer documentation for your OAuth server.
  # Included in the /.well-known/oauth-authorization-server response.
  # config.authorization_server_documentation = "https://example.com/docs/oauth"

  # Note: scopes_supported in the metadata response is automatically derived
  # from the keys of config.scopes (see Scopes section above).

  # ==========================================================================
  # Dynamic Client Registration (RFC 7591)
  # ==========================================================================

  # Enable dynamic client registration endpoint (/register) (default: true).
  # When enabled, clients can register programmatically via POST requests.
  # config.dcr_enabled = true

  # Require an initial access token for client registration (default: false).
  # When enabled, registration requests must include a Bearer token.
  # config.dcr_require_initial_access_token = false

  # Validator proc for initial access tokens.
  # Must return true if the token is valid, false otherwise.
  # Example:
  # config.dcr_initial_access_token_validator = ->(token) {
  #   token == ENV["REGISTRATION_ACCESS_TOKEN"]
  # }

  # Allowed grant types for dynamically registered clients.
  # config.dcr_allowed_grant_types = %w[authorization_code refresh_token]

  # Allowed response types for dynamically registered clients.
  # config.dcr_allowed_response_types = %w[code]

  # Allowed token endpoint authentication methods.
  # Options: none, client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt
  # config.dcr_allowed_token_endpoint_auth_methods = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt]

  # Client secret expiration duration in seconds (nil = never expires).
  # config.dcr_client_secret_expiration = nil

  # JWKS for verifying software statements (signed JWTs with client metadata).
  # Set to a JWKS hash to enable software statement verification.
  # config.dcr_software_statement_jwks = nil

  # Require software statements for client registration.
  # When enabled, registration requests must include a valid software_statement.
  # config.dcr_software_statement_required = false

  # Cache TTL in seconds for fetched JWKS from jwks_uri (default: 1 hour).
  # config.dcr_jwks_cache_ttl = 3600

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
