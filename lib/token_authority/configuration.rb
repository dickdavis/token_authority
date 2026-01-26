# frozen_string_literal: true

module TokenAuthority
  # Configuration class for TokenAuthority engine settings.
  #
  # This class manages all configuration options for the OAuth 2.1 provider,
  # including JWT settings, user authentication integration, UI customization,
  # and RFC-specific feature flags.
  #
  # Configuration is typically set in a Rails initializer using a configure block
  # that yields this configuration object.
  #
  # @example Minimal configuration
  #   TokenAuthority.configure do |config|
  #     config.secret_key = Rails.application.credentials.secret_key_base
  #
  #     config.scopes = {
  #       "read" => "Read access to your data",
  #       "write" => "Write access to your data"
  #     }
  #
  #     config.resources = {
  #       api: {
  #         resource: "https://example.com/api",
  #         resource_name: "My API",
  #         scopes_supported: %w[read write],
  #         authorization_servers: ["https://example.com"]
  #       }
  #     }
  #   end
  #
  # @since 0.2.0
  class Configuration
    # ==========================================================================
    # General
    # ==========================================================================

    # @!attribute [rw] secret_key
    #   The secret key used for JWT signing and HMAC operations.
    #   This should be a secure random string, typically derived from Rails credentials.
    #   @return [String] the secret key
    attr_accessor :secret_key

    # @!attribute [rw] event_logging_enabled
    #   Enable structured event logging for OAuth flows and security events.
    #   @return [Boolean] true if enabled (default: true)
    attr_accessor :event_logging_enabled

    # @!attribute [rw] event_logging_debug_events
    #   Enable debug-level event logging for troubleshooting.
    #   @return [Boolean] true if enabled (default: false)
    attr_accessor :event_logging_debug_events

    # @!attribute [rw] instrumentation_enabled
    #   Enable ActiveSupport::Notifications instrumentation for performance monitoring.
    #   @return [Boolean] true if enabled (default: true)
    attr_accessor :instrumentation_enabled

    # ==========================================================================
    # User Authentication
    # ==========================================================================

    # @!attribute [rw] authenticatable_controller
    #   The controller class name that provides authentication methods.
    #   Must implement `authenticate_user!` and `current_user` methods.
    #   @return [String] controller class name (default: "ApplicationController")
    attr_accessor :authenticatable_controller

    # @!attribute [rw] user_class
    #   The user model class name in the host application.
    #   @return [String] user class name (default: "User")
    attr_accessor :user_class

    # ==========================================================================
    # UI/Layout
    # ==========================================================================

    # @!attribute [rw] consent_page_layout
    #   The layout to use for the OAuth consent screen.
    #   @return [String] layout name (default: "application")
    attr_accessor :consent_page_layout

    # @!attribute [rw] error_page_layout
    #   The layout to use for OAuth error pages.
    #   @return [String] layout name (default: "application")
    attr_accessor :error_page_layout

    # ==========================================================================
    # Scopes
    # ==========================================================================

    # @!attribute [rw] scopes
    #   Hash mapping scope strings to human-readable descriptions.
    #   Set to nil or empty hash to disable scopes.
    #   @example
    #     config.scopes = {
    #       "read" => "Read access to your data",
    #       "write" => "Write access to your data"
    #     }
    #   @return [Hash{String => String}, nil] scope mappings
    attr_accessor :scopes

    # @!attribute [rw] require_scope
    #   Whether clients must include a scope parameter in authorization requests.
    #   @return [Boolean] true if scope is required (default: true)
    attr_accessor :require_scope

    # ==========================================================================
    # Resources (RFC 9728 / RFC 8707)
    # ==========================================================================

    # @!attribute [rw] resources
    #   Protected resource metadata keyed by resource identifier (RFC 9728).
    #
    #   Maps resource symbols to metadata hashes. When a request arrives at
    #   the /.well-known/oauth-protected-resource endpoint, the controller extracts
    #   the subdomain and looks it up in this hash. If no match is found, the first
    #   resource in the hash is used as the default.
    #
    #   For single-resource deployments, simply configure one entry - it will be used
    #   for all requests regardless of subdomain.
    #
    #   Each entry must include the :resource field (required per RFC 9728). The
    #   validate! method raises ConfigurationError if any entry is missing this field.
    #   All other fields are optional and will be omitted from responses if not set.
    #
    #   == Available Resource Options
    #
    #   [resource]                  (Required) The protected resource URI. Used as the
    #                               audience (aud) claim in JWT access tokens.
    #   [resource_name]             Human-readable name shown on the consent screen.
    #   [scopes_supported]          Array of scope strings this resource accepts.
    #   [authorization_servers]     Array of authorization server URLs. The first entry
    #                               is used as the issuer (iss) claim if token_issuer_url
    #                               is not set. Also appears in RFC 9728 metadata responses.
    #   [bearer_methods_supported]  Array of supported bearer token methods (e.g., ["header"]).
    #   [jwks_uri]                  URI for the JSON Web Key Set endpoint.
    #   [resource_documentation]    URL for API documentation.
    #   [resource_policy_uri]       URL for the privacy policy.
    #   [resource_tos_uri]          URL for terms of service.
    #
    #   @example Single resource with all options
    #     config.resources = {
    #       api: {
    #         resource: "https://example.com/api",
    #         resource_name: "Example API",
    #         scopes_supported: %w[read write admin],
    #         authorization_servers: ["https://example.com"],
    #         bearer_methods_supported: ["header"],
    #         jwks_uri: "https://example.com/.well-known/jwks.json",
    #         resource_documentation: "https://example.com/docs/api",
    #         resource_policy_uri: "https://example.com/privacy",
    #         resource_tos_uri: "https://example.com/terms"
    #       }
    #     }
    #
    #   @example Multi-resource deployment with subdomains
    #     config.resources = {
    #       api: {
    #         resource: "https://api.example.com",
    #         resource_name: "REST API",
    #         scopes_supported: %w[api:read api:write],
    #         authorization_servers: ["https://auth.example.com"]
    #       },
    #       mcp: {
    #         resource: "https://mcp.example.com",
    #         resource_name: "MCP Server",
    #         scopes_supported: %w[mcp:tools mcp:prompts mcp:resources],
    #         authorization_servers: ["https://auth.example.com"]
    #       }
    #     }
    #
    #   @return [Hash{Symbol => Hash}, nil] resource identifier to metadata mapping
    attr_accessor :resources

    # @!attribute [rw] require_resource
    #   Whether clients must include a resource parameter in authorization requests.
    #   @return [Boolean] true if resource is required (default: true)
    attr_accessor :require_resource

    # ==========================================================================
    # JWT Access Tokens (RFC 9068)
    # ==========================================================================

    # @!attribute [rw] token_audience_url
    #   The default audience (aud) claim for JWT access tokens per RFC 9068.
    #   Identifies the intended recipient of the token (typically the API server).
    #   @return [String, nil] the audience URL
    attr_accessor :token_audience_url

    # @!attribute [rw] token_issuer_url
    #   The issuer (iss) claim for JWT access tokens per RFC 9068.
    #   Identifies the authorization server that issued the token.
    #   @return [String, nil] the issuer URL
    attr_accessor :token_issuer_url

    # @!attribute [rw] default_access_token_duration
    #   Default lifetime for access tokens in seconds.
    #   @return [Integer] duration in seconds (default: 300)
    attr_accessor :default_access_token_duration

    # @!attribute [rw] default_refresh_token_duration
    #   Default lifetime for refresh tokens in seconds.
    #   @return [Integer] duration in seconds (default: 1,209,600)
    attr_accessor :default_refresh_token_duration

    # ==========================================================================
    # Server Metadata (RFC 8414)
    # ==========================================================================

    # @!attribute [rw] authorization_server_documentation
    #   URL for service documentation in authorization server metadata per RFC 8414.
    #   @return [String, nil] documentation URL
    attr_accessor :authorization_server_documentation

    # ==========================================================================
    # Dynamic Client Registration (RFC 7591)
    # ==========================================================================

    # @!attribute [rw] dcr_enabled
    #   Enable dynamic client registration per RFC 7591.
    #   @return [Boolean] true if enabled (default: true)
    attr_accessor :dcr_enabled

    # @!attribute [rw] dcr_require_initial_access_token
    #   Require initial access token for client registration per RFC 7591.
    #   @return [Boolean] true if required (default: false)
    attr_accessor :dcr_require_initial_access_token

    # @!attribute [rw] dcr_initial_access_token_validator
    #   Callable object to validate initial access tokens.
    #   Should accept a token string and return true/false.
    #   @return [Proc, nil] validator callable
    attr_accessor :dcr_initial_access_token_validator

    # @!attribute [rw] dcr_allowed_grant_types
    #   Array of grant types allowed during client registration per RFC 7591.
    #   @return [Array<String>] allowed grant types
    attr_accessor :dcr_allowed_grant_types

    # @!attribute [rw] dcr_allowed_response_types
    #   Array of response types allowed during client registration per RFC 7591.
    #   @return [Array<String>] allowed response types
    attr_accessor :dcr_allowed_response_types

    # @!attribute [rw] dcr_allowed_scopes
    #   Array of scopes allowed during client registration per RFC 7591.
    #   @return [Array<String>, nil] allowed scopes
    attr_accessor :dcr_allowed_scopes

    # @!attribute [rw] dcr_allowed_token_endpoint_auth_methods
    #   Array of token endpoint authentication methods allowed per RFC 7591.
    #   @return [Array<String>] allowed auth methods
    attr_accessor :dcr_allowed_token_endpoint_auth_methods

    # @!attribute [rw] dcr_client_secret_expiration
    #   Duration in seconds before client secrets expire, or nil for no expiration.
    #   @return [Integer, nil] expiration duration in seconds
    attr_accessor :dcr_client_secret_expiration

    # @!attribute [rw] dcr_software_statement_jwks
    #   JWKS for verifying software statements during registration per RFC 7591.
    #   @return [Hash, nil] JWKS
    attr_accessor :dcr_software_statement_jwks

    # @!attribute [rw] dcr_software_statement_required
    #   Require software statements during client registration per RFC 7591.
    #   @return [Boolean] true if required (default: false)
    attr_accessor :dcr_software_statement_required

    # @!attribute [rw] dcr_jwks_cache_ttl
    #   Time-to-live for cached JWKS in seconds.
    #   @return [Integer] TTL in seconds (default: 3600)
    attr_accessor :dcr_jwks_cache_ttl

    # ==========================================================================
    # Client Metadata Document (draft-ietf-oauth-client-id-metadata-document)
    # ==========================================================================

    # @!attribute [rw] client_metadata_document_enabled
    #   Enable support for client metadata documents (URL-based client IDs).
    #   @return [Boolean] true if enabled (default: true)
    attr_accessor :client_metadata_document_enabled

    # @!attribute [rw] client_metadata_document_cache_ttl
    #   Time-to-live for cached client metadata documents in seconds.
    #   @return [Integer] TTL in seconds (default: 3600)
    attr_accessor :client_metadata_document_cache_ttl

    # @!attribute [rw] client_metadata_document_max_response_size
    #   Maximum size in bytes for client metadata document HTTP responses.
    #   @return [Integer] max size in bytes (default: 5120)
    attr_accessor :client_metadata_document_max_response_size

    # @!attribute [rw] client_metadata_document_allowed_hosts
    #   Whitelist of hosts allowed for client metadata document URLs.
    #   @return [Array<String>, nil] allowed hosts
    attr_accessor :client_metadata_document_allowed_hosts

    # @!attribute [rw] client_metadata_document_blocked_hosts
    #   Blacklist of hosts blocked for client metadata document URLs.
    #   @return [Array<String>] blocked hosts (default: [])
    attr_accessor :client_metadata_document_blocked_hosts

    # @!attribute [rw] client_metadata_document_connect_timeout
    #   Connection timeout in seconds for fetching client metadata documents.
    #   @return [Integer] timeout in seconds (default: 5)
    attr_accessor :client_metadata_document_connect_timeout

    # @!attribute [rw] client_metadata_document_read_timeout
    #   Read timeout in seconds for fetching client metadata documents.
    #   @return [Integer] timeout in seconds (default: 5)
    attr_accessor :client_metadata_document_read_timeout

    def initialize
      # General
      @secret_key = nil
      @event_logging_enabled = true
      @event_logging_debug_events = false
      @instrumentation_enabled = true

      # User Authentication
      @authenticatable_controller = "ApplicationController"
      @user_class = "User"

      # UI/Layout
      @consent_page_layout = "application"
      @error_page_layout = "application"

      # Scopes
      @scopes = {}
      @require_scope = true

      # Resources
      @resources = {}
      @require_resource = true

      # JWT Access Tokens (RFC 9068)
      @token_audience_url = nil
      @token_issuer_url = nil
      @default_access_token_duration = 300 # 5 minutes in seconds
      @default_refresh_token_duration = 1_209_600 # 14 days in seconds

      # Server Metadata (RFC 8414)
      @authorization_server_documentation = nil

      # Dynamic Client Registration (RFC 7591)
      @dcr_enabled = true
      @dcr_require_initial_access_token = false
      @dcr_initial_access_token_validator = nil
      @dcr_allowed_grant_types = %w[authorization_code refresh_token]
      @dcr_allowed_response_types = %w[code]
      @dcr_allowed_scopes = nil
      @dcr_allowed_token_endpoint_auth_methods = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt]
      @dcr_client_secret_expiration = nil
      @dcr_software_statement_jwks = nil
      @dcr_software_statement_required = false
      @dcr_jwks_cache_ttl = 3600

      # Client Metadata Document (draft-ietf-oauth-client-id-metadata-document)
      @client_metadata_document_enabled = true
      @client_metadata_document_cache_ttl = 3600
      @client_metadata_document_max_response_size = 5120
      @client_metadata_document_allowed_hosts = nil
      @client_metadata_document_blocked_hosts = []
      @client_metadata_document_connect_timeout = 5
      @client_metadata_document_read_timeout = 5
    end

    # Checks whether the scopes feature is enabled.
    # Scopes are considered enabled when the scopes attribute is a non-empty hash.
    #
    # @return [Boolean] true if scopes are enabled
    def scopes_enabled?
      scopes.is_a?(Hash) && scopes.any?
    end

    # Checks whether resources are configured.
    # Resources are enabled when at least one resource is configured.
    #
    # @return [Boolean] true if resources are enabled
    def resources_enabled?
      resource_registry.any?
    end

    # Builds a mapping of resource URIs to display names from resource configuration.
    #
    # This derives the RFC 8707 resource allowlist from the resources configuration.
    # Each configured resource's :resource URI becomes a key, with its :resource_name
    # (or the URI itself) as the display name.
    #
    # The result is used for:
    # - Validating resource indicators in authorization requests
    # - Displaying resource names on the consent screen
    #
    # @return [Hash{String => String}] mapping of resource URIs to display names
    #
    # @example With resources configured
    #   config.resources = {
    #     api: { resource: "https://api.example.com", resource_name: "REST API" },
    #     mcp: { resource: "https://mcp.example.com", resource_name: "MCP Server" }
    #   }
    #   config.resource_registry
    #   # => { "https://api.example.com" => "REST API", "https://mcp.example.com" => "MCP Server" }
    def resource_registry
      return {} unless resources.is_a?(Hash)

      resources.each_with_object({}) do |(_key, config), registry|
        next unless config.is_a?(Hash) && config[:resource].present?

        uri = normalize_resource_uri(config[:resource])
        registry[uri] = config[:resource_name] || uri
      end
    end

    # Normalizes a resource URI for consistent comparison.
    #
    # This method removes trailing slashes from resource URIs to ensure consistent
    # matching between configured resources and client-provided resource parameters.
    #
    # @param uri [String] the resource URI to normalize
    # @return [String] the normalized URI without trailing slash
    #
    # @example
    #   normalize_resource_uri("https://mcp.example.com/")
    #   # => "https://mcp.example.com"
    def normalize_resource_uri(uri)
      return uri if uri.blank?

      uri.to_s.chomp("/")
    end

    # Validates the configuration for internal consistency.
    # Ensures that required features are properly configured before use.
    #
    # @raise [ConfigurationError] if require_scope is true but scopes are not configured
    # @raise [ConfigurationError] if require_resource is true but no resources are configured
    # @raise [ConfigurationError] if any resource entry is missing the required :resource field
    # @raise [ConfigurationError] if no issuer URL is available
    # @return [void]
    def validate!
      if require_scope && !scopes_enabled?
        raise ConfigurationError, "require_scope is true but no scopes are configured"
      end

      # Validate resource entries first (before checking if any valid resources exist)
      if resources.is_a?(Hash)
        resources.each do |key, config|
          next unless config.is_a?(Hash)

          if config[:resource].blank?
            raise ConfigurationError, "resource :#{key} is missing the required :resource field"
          end
        end
      end

      if require_resource && !resources_enabled?
        raise ConfigurationError, "require_resource is true but no resources are configured"
      end

      if issuer_url.blank?
        raise ConfigurationError,
          "no issuer URL configured: set token_issuer_url or add authorization_servers to a resource"
      end
    end

    # Resolves protected resource configuration using subdomain-aware lookup.
    #
    # Lookup strategy:
    # 1. If resource_key is present, look it up as a symbol in resources
    # 2. If not found or resource_key is blank, use the first resource in the hash
    # 3. If resources is empty, return nil (controller will 404)
    #
    # @param resource_key [String, nil] the subdomain or lookup key
    # @return [Hash, nil] the resource metadata, or nil if not configured
    #
    # @example Subdomain-specific lookup
    #   config.resources = { api: { resource: "https://api.example.com" } }
    #   config.protected_resource_for("api")  # => { resource: "https://api.example.com" }
    #
    # @example Fallback to first resource
    #   config.resources = { api: { resource: "https://api.example.com" } }
    #   config.protected_resource_for("unknown")  # => { resource: "https://api.example.com" }
    #
    # @example Not configured
    #   config.resources = {}
    #   config.protected_resource_for(nil)  # => nil (will cause 404)
    def protected_resource_for(resource_key)
      return nil unless resources.is_a?(Hash) && resources.any?

      # Try subdomain lookup first, fall back to first resource
      if resource_key.present?
        resources[resource_key.to_sym] || resources.values.first
      else
        resources.values.first
      end
    end

    # Returns the effective audience URL for JWT tokens.
    #
    # The audience URL is determined as follows:
    # 1. If token_audience_url is set, use that value
    # 2. Otherwise, derive from the first resource's :resource URL
    #
    # @return [String, nil] the audience URL, or nil if not configured
    #
    # @example Explicit audience URL
    #   config.token_audience_url = "https://api.example.com"
    #   config.audience_url  # => "https://api.example.com"
    #
    # @example Derived from resources
    #   config.token_audience_url = nil
    #   config.resources = { api: { resource: "https://api.example.com" } }
    #   config.audience_url  # => "https://api.example.com"
    def audience_url
      return token_audience_url if token_audience_url.present?

      # Derive from first resource's :resource URL
      return nil unless resources.is_a?(Hash) && resources.any?

      first_resource = resources.values.first
      return nil unless first_resource.is_a?(Hash)

      first_resource[:resource]
    end

    # Returns the effective issuer URL for JWT tokens.
    #
    # The issuer URL is determined as follows:
    # 1. If token_issuer_url is set, use that value
    # 2. Otherwise, derive from the first resource's authorization_servers
    #
    # @return [String, nil] the issuer URL, or nil if not configured
    #
    # @example Explicit issuer URL
    #   config.token_issuer_url = "https://auth.example.com"
    #   config.issuer_url  # => "https://auth.example.com"
    #
    # @example Derived from authorization_servers
    #   config.token_issuer_url = nil
    #   config.resources = { api: { authorization_servers: ["https://auth.example.com"] } }
    #   config.issuer_url  # => "https://auth.example.com"
    def issuer_url
      return token_issuer_url if token_issuer_url.present?

      # Derive from first resource's authorization_servers
      return nil unless resources.is_a?(Hash) && resources.any?

      first_resource = resources.values.first
      return nil unless first_resource.is_a?(Hash)

      auth_servers = first_resource[:authorization_servers]
      return nil unless auth_servers.is_a?(Array) && auth_servers.any?

      auth_servers.first
    end
  end

  class << self
    # Returns the current configuration instance.
    # Creates a new configuration with default values if one doesn't exist.
    #
    # @return [Configuration] the configuration instance
    def config
      @config ||= Configuration.new
    end

    # Yields the configuration instance for setup in initializers.
    # This is the primary way to configure TokenAuthority in a Rails application.
    #
    # @example
    #   TokenAuthority.configure do |config|
    #     config.secret_key = Rails.application.credentials.secret_key_base
    #     config.user_class = "User"
    #   end
    #
    # @yield [config] configuration block
    # @yieldparam config [Configuration] the configuration instance to modify
    # @return [void]
    def configure
      yield(config)
    end
  end
end
