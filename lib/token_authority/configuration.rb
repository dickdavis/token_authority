# frozen_string_literal: true

module TokenAuthority
  class Configuration
    # JWT Configuration
    attr_accessor :audience_url, :issuer_url, :secret_key

    # User Authentication
    attr_accessor :authenticatable_controller, :user_class

    # UI/Layout
    attr_accessor :consent_page_layout, :error_page_layout

    # Server Metadata (RFC 8414)
    attr_accessor :scopes_supported, :service_documentation

    def initialize
      # JWT Configuration
      @audience_url = nil
      @issuer_url = nil
      @secret_key = nil

      # User Authentication
      @authenticatable_controller = "ApplicationController"
      @user_class = "User"

      # UI/Layout
      @consent_page_layout = "application"
      @error_page_layout = "application"

      # Server Metadata (RFC 8414)
      @scopes_supported = []
      @service_documentation = nil
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
