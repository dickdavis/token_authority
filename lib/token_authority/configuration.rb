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
    attr_accessor :rfc_8414_scopes_supported, :rfc_8414_service_documentation

    # Protected Resource Metadata (RFC 9728)
    attr_accessor :rfc_9728_resource, :rfc_9728_scopes_supported, :rfc_9728_authorization_servers,
      :rfc_9728_bearer_methods_supported, :rfc_9728_jwks_uri, :rfc_9728_resource_name,
      :rfc_9728_resource_documentation, :rfc_9728_resource_policy_uri, :rfc_9728_resource_tos_uri

    def initialize
      # General
      @secret_key = nil

      # JWT Access Tokens (RFC 9068)
      @rfc_9068_audience_url = nil
      @rfc_9068_issuer_url = nil
      @rfc_9068_default_access_token_duration = 300 # 5 minutes in seconds
      @rfc_9068_default_refresh_token_duration = 1_209_600 # 14 days in seconds

      # User Authentication
      @authenticatable_controller = "ApplicationController"
      @user_class = "User"

      # UI/Layout
      @consent_page_layout = "application"
      @error_page_layout = "application"

      # Server Metadata (RFC 8414)
      @rfc_8414_scopes_supported = []
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
