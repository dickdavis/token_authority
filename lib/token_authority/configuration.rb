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
  # @example Basic configuration
  #   TokenAuthority.configure do |config|
  #     config.secret_key = Rails.application.credentials.secret_key_base
  #     config.user_class = "User"
  #     config.rfc_9068_audience_url = "https://api.example.com"
  #     config.rfc_9068_issuer_url = "https://example.com"
  #   end
  #
  # @example Enabling scopes
  #   TokenAuthority.configure do |config|
  #     config.scopes = {
  #       "read" => "Read access to your data",
  #       "write" => "Write access to your data"
  #     }
  #     config.require_scope = true
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
    #   @return [Boolean] true if scope is required (default: false)
    attr_accessor :require_scope

    # ==========================================================================
    # Resources (RFC 9728 / RFC 8707)
    # ==========================================================================

    # @!attribute [rw] resources
    #   Protected resource metadata keyed by subdomain (RFC 9728).
    #
    #   Maps subdomain symbols to resource metadata hashes. When a request arrives at
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
    #   @example Single resource deployment
    #     config.resources = {
    #       api: {
    #         resource: "https://api.example.com",
    #         resource_name: "Example API",
    #         scopes_supported: %w[read write admin]
    #       }
    #     }
    #
    #   @example Multi-resource deployment with subdomains
    #     config.resources = {
    #       api: {
    #         resource: "https://api.example.com",
    #         resource_name: "REST API",
    #         scopes_supported: %w[api:read api:write]
    #       },
    #       mcp: {
    #         resource: "https://mcp.example.com",
    #         resource_name: "MCP Server",
    #         scopes_supported: %w[mcp:tools mcp:prompts mcp:resources]
    #       }
    #     }
    #
    #   @return [Hash{Symbol => Hash}, nil] subdomain-to-metadata mapping
    attr_accessor :resources

    # @!attribute [rw] require_resource
    #   Whether clients must include a resource parameter in authorization requests.
    #   @return [Boolean] true if resource is required (default: false)
    attr_accessor :require_resource

    # ==========================================================================
    # JWT Access Tokens (RFC 9068)
    # ==========================================================================

    # @!attribute [rw] rfc_9068_audience_url
    #   The default audience (aud) claim for JWT access tokens per RFC 9068.
    #   Identifies the intended recipient of the token (typically the API server).
    #   @return [String, nil] the audience URL
    attr_accessor :rfc_9068_audience_url

    # @!attribute [rw] rfc_9068_issuer_url
    #   The issuer (iss) claim for JWT access tokens per RFC 9068.
    #   Identifies the authorization server that issued the token.
    #   @return [String, nil] the issuer URL
    attr_accessor :rfc_9068_issuer_url

    # @!attribute [rw] rfc_9068_default_access_token_duration
    #   Default lifetime for access tokens in seconds.
    #   @return [Integer] duration in seconds (default: 300)
    attr_accessor :rfc_9068_default_access_token_duration

    # @!attribute [rw] rfc_9068_default_refresh_token_duration
    #   Default lifetime for refresh tokens in seconds.
    #   @return [Integer] duration in seconds (default: 1,209,600)
    attr_accessor :rfc_9068_default_refresh_token_duration

    # ==========================================================================
    # Server Metadata (RFC 8414)
    # ==========================================================================

    # @!attribute [rw] rfc_8414_service_documentation
    #   URL for service documentation in authorization server metadata per RFC 8414.
    #   @return [String, nil] documentation URL
    attr_accessor :rfc_8414_service_documentation

    # ==========================================================================
    # Dynamic Client Registration (RFC 7591)
    # ==========================================================================

    # @!attribute [rw] rfc_7591_enabled
    #   Enable dynamic client registration per RFC 7591.
    #   @return [Boolean] true if enabled (default: false)
    attr_accessor :rfc_7591_enabled

    # @!attribute [rw] rfc_7591_require_initial_access_token
    #   Require initial access token for client registration per RFC 7591.
    #   @return [Boolean] true if required (default: false)
    attr_accessor :rfc_7591_require_initial_access_token

    # @!attribute [rw] rfc_7591_initial_access_token_validator
    #   Callable object to validate initial access tokens.
    #   Should accept a token string and return true/false.
    #   @return [Proc, nil] validator callable
    attr_accessor :rfc_7591_initial_access_token_validator

    # @!attribute [rw] rfc_7591_allowed_grant_types
    #   Array of grant types allowed during client registration per RFC 7591.
    #   @return [Array<String>] allowed grant types
    attr_accessor :rfc_7591_allowed_grant_types

    # @!attribute [rw] rfc_7591_allowed_response_types
    #   Array of response types allowed during client registration per RFC 7591.
    #   @return [Array<String>] allowed response types
    attr_accessor :rfc_7591_allowed_response_types

    # @!attribute [rw] rfc_7591_allowed_scopes
    #   Array of scopes allowed during client registration per RFC 7591.
    #   @return [Array<String>, nil] allowed scopes
    attr_accessor :rfc_7591_allowed_scopes

    # @!attribute [rw] rfc_7591_allowed_token_endpoint_auth_methods
    #   Array of token endpoint authentication methods allowed per RFC 7591.
    #   @return [Array<String>] allowed auth methods
    attr_accessor :rfc_7591_allowed_token_endpoint_auth_methods

    # @!attribute [rw] rfc_7591_client_secret_expiration
    #   Duration in seconds before client secrets expire, or nil for no expiration.
    #   @return [Integer, nil] expiration duration in seconds
    attr_accessor :rfc_7591_client_secret_expiration

    # @!attribute [rw] rfc_7591_software_statement_jwks
    #   JWKS for verifying software statements during registration per RFC 7591.
    #   @return [Hash, nil] JWKS
    attr_accessor :rfc_7591_software_statement_jwks

    # @!attribute [rw] rfc_7591_software_statement_required
    #   Require software statements during client registration per RFC 7591.
    #   @return [Boolean] true if required (default: false)
    attr_accessor :rfc_7591_software_statement_required

    # @!attribute [rw] rfc_7591_jwks_cache_ttl
    #   Time-to-live for cached JWKS in seconds.
    #   @return [Integer] TTL in seconds (default: 3600)
    attr_accessor :rfc_7591_jwks_cache_ttl

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
      @scopes = nil
      @require_scope = false

      # Resources
      @resources = {}
      @require_resource = false

      # JWT Access Tokens (RFC 9068)
      @rfc_9068_audience_url = nil
      @rfc_9068_issuer_url = nil
      @rfc_9068_default_access_token_duration = 300 # 5 minutes in seconds
      @rfc_9068_default_refresh_token_duration = 1_209_600 # 14 days in seconds

      # Server Metadata (RFC 8414)
      @rfc_8414_service_documentation = nil

      # Dynamic Client Registration (RFC 7591)
      @rfc_7591_enabled = false
      @rfc_7591_require_initial_access_token = false
      @rfc_7591_initial_access_token_validator = nil
      @rfc_7591_allowed_grant_types = %w[authorization_code refresh_token]
      @rfc_7591_allowed_response_types = %w[code]
      @rfc_7591_allowed_scopes = nil
      @rfc_7591_allowed_token_endpoint_auth_methods = %w[none client_secret_basic client_secret_post client_secret_jwt private_key_jwt]
      @rfc_7591_client_secret_expiration = nil
      @rfc_7591_software_statement_jwks = nil
      @rfc_7591_software_statement_required = false
      @rfc_7591_jwks_cache_ttl = 3600

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

        uri = config[:resource]
        registry[uri] = config[:resource_name] || uri
      end
    end

    # Validates the configuration for internal consistency.
    # Ensures that required features are properly configured before use.
    #
    # @raise [ConfigurationError] if require_scope is true but scopes are not configured
    # @raise [ConfigurationError] if require_resource is true but no resources are configured
    # @raise [ConfigurationError] if any resource entry is missing the required :resource field
    # @return [void]
    def validate!
      if require_scope && !scopes_enabled?
        raise ConfigurationError, "require_scope is true but no scopes are configured"
      end

      if require_resource && !resources_enabled?
        raise ConfigurationError, "require_resource is true but no resources are configured"
      end

      if resources.is_a?(Hash)
        resources.each do |key, config|
          next unless config.is_a?(Hash)

          if config[:resource].blank?
            raise ConfigurationError, "resource :#{key} is missing the required :resource field"
          end
        end
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
