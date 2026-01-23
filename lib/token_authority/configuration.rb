# frozen_string_literal: true

module TokenAuthority
  class Configuration
    # General
    attr_accessor :secret_key

    # JWT Access Tokens (RFC 9068)
    attr_accessor :rfc_9068_audience_url, :rfc_9068_issuer_url,
      :rfc_9068_default_access_token_duration, :rfc_9068_default_refresh_token_duration

    # User Authentication
    attr_accessor :authenticatable_controller, :user_class

    # UI/Layout
    attr_accessor :consent_page_layout, :error_page_layout

    # Server Metadata (RFC 8414)
    attr_accessor :rfc_8414_service_documentation

    # Scopes
    # scopes: Hash mapping scope strings to display names
    #   - nil or {} = scopes disabled
    #   - { "read" => "Read access", "write" => "Write access" } = only these scopes allowed
    # require_scope: Whether the scope param is required (default: false)
    attr_accessor :scopes, :require_scope

    # Protected Resource Metadata (RFC 9728)
    attr_accessor :rfc_9728_resource, :rfc_9728_scopes_supported, :rfc_9728_authorization_servers,
      :rfc_9728_bearer_methods_supported, :rfc_9728_jwks_uri, :rfc_9728_resource_name,
      :rfc_9728_resource_documentation, :rfc_9728_resource_policy_uri, :rfc_9728_resource_tos_uri

    # Dynamic Client Registration (RFC 7591)
    attr_accessor :rfc_7591_enabled,
      :rfc_7591_require_initial_access_token,
      :rfc_7591_initial_access_token_validator,
      :rfc_7591_allowed_grant_types,
      :rfc_7591_allowed_response_types,
      :rfc_7591_allowed_scopes,
      :rfc_7591_allowed_token_endpoint_auth_methods,
      :rfc_7591_client_secret_expiration,
      :rfc_7591_software_statement_jwks,
      :rfc_7591_software_statement_required,
      :rfc_7591_jwks_cache_ttl

    # Client Metadata Document (draft-ietf-oauth-client-id-metadata-document)
    attr_accessor :client_metadata_document_enabled,
      :client_metadata_document_cache_ttl,
      :client_metadata_document_max_response_size,
      :client_metadata_document_allowed_hosts,
      :client_metadata_document_blocked_hosts,
      :client_metadata_document_connect_timeout,
      :client_metadata_document_read_timeout

    # Resource Indicators (RFC 8707)
    # rfc_8707_resources: Hash mapping resource URIs to display names
    #   - nil or {} = resource indicators disabled
    #   - { "https://api.example.com" => "Main API" } = only these resources allowed
    # rfc_8707_require_resource: Whether the resource param is required (default: false)
    attr_accessor :rfc_8707_resources, :rfc_8707_require_resource

    # Event Logging
    # event_logging_enabled: Whether to emit and log events (default: true)
    # event_logging_debug_events: Whether to emit debug events (default: false)
    attr_accessor :event_logging_enabled, :event_logging_debug_events

    def initialize
      # General
      @secret_key = nil

      # User Authentication
      @authenticatable_controller = "ApplicationController"
      @user_class = "User"

      # UI/Layout
      @consent_page_layout = "application"
      @error_page_layout = "application"

      # Scopes
      @scopes = nil
      @require_scope = false

      # JWT Access Tokens (RFC 9068)
      @rfc_9068_audience_url = nil
      @rfc_9068_issuer_url = nil
      @rfc_9068_default_access_token_duration = 300 # 5 minutes in seconds
      @rfc_9068_default_refresh_token_duration = 1_209_600 # 14 days in seconds

      # Server Metadata (RFC 8414)
      @rfc_8414_service_documentation = nil

      # Protected Resource Metadata (RFC 9728)
      @rfc_9728_resource = nil
      @rfc_9728_scopes_supported = nil
      @rfc_9728_authorization_servers = nil
      @rfc_9728_bearer_methods_supported = nil
      @rfc_9728_jwks_uri = nil
      @rfc_9728_resource_name = nil
      @rfc_9728_resource_documentation = nil
      @rfc_9728_resource_policy_uri = nil
      @rfc_9728_resource_tos_uri = nil

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

      # Resource Indicators (RFC 8707)
      @rfc_8707_resources = nil
      @rfc_8707_require_resource = false

      # Event Logging
      @event_logging_enabled = true
      @event_logging_debug_events = false
    end

    # Returns true if scopes are enabled
    def scopes_enabled?
      scopes.is_a?(Hash) && scopes.any?
    end

    # Returns true if RFC 8707 resource indicators are enabled
    def rfc_8707_enabled?
      rfc_8707_resources.is_a?(Hash) && rfc_8707_resources.any?
    end

    # Validates configuration and raises errors for invalid combinations
    def validate!
      if require_scope && !scopes_enabled?
        raise ConfigurationError, "require_scope is true but no scopes are configured"
      end

      if rfc_8707_require_resource && !rfc_8707_enabled?
        raise ConfigurationError, "rfc_8707_require_resource is true but no rfc_8707_resources are configured"
      end
    end
  end

  class << self
    def config
      @config ||= Configuration.new
    end

    def configure
      yield(config)
    end
  end
end
