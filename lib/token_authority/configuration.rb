# frozen_string_literal: true

module TokenAuthority
  class Configuration
    attr_accessor :audience_url, :authenticatable_controller, :consent_page_layout,
      :error_page_layout, :issuer_url, :secret_key, :user_class

    def initialize
      @audience_url = nil
      @authenticatable_controller = "ApplicationController"
      @consent_page_layout = "application"
      @error_page_layout = "application"
      @issuer_url = nil
      @secret_key = nil
      @user_class = "User"
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
