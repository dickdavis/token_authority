# frozen_string_literal: true

module TokenAuthority
  class Configuration
    # General
    attr_accessor :secret_key

    # Token
    attr_accessor :audience_url, :issuer_url, :default_access_token_duration, :default_refresh_token_duration

    # User Authentication
    attr_accessor :authenticatable_controller, :user_class

    # UI/Layout
    attr_accessor :consent_page_layout, :error_page_layout

    # Server Metadata (RFC 8414)
    attr_accessor :scopes_supported, :service_documentation

    # Protected Resource Metadata (RFC 9728)
    attr_accessor :resource_url, :resource_scopes_supported, :resource_authorization_servers,
      :resource_bearer_methods_supported, :resource_jwks_uri, :resource_name,
      :resource_documentation, :resource_policy_uri, :resource_tos_uri

    def initialize
      # General
      @secret_key = nil

      # Token
      @audience_url = nil
      @issuer_url = nil
      @default_access_token_duration = 300 # 5 minutes in seconds
      @default_refresh_token_duration = 1_209_600 # 14 days in seconds

      # User Authentication
      @authenticatable_controller = "ApplicationController"
      @user_class = "User"

      # UI/Layout
      @consent_page_layout = "application"
      @error_page_layout = "application"

      # Server Metadata (RFC 8414)
      @scopes_supported = []
      @service_documentation = nil

      # Protected Resource Metadata (RFC 9728)
      @resource_url = nil
      @resource_scopes_supported = nil
      @resource_authorization_servers = nil
      @resource_bearer_methods_supported = nil
      @resource_jwks_uri = nil
      @resource_name = nil
      @resource_documentation = nil
      @resource_policy_uri = nil
      @resource_tos_uri = nil
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
