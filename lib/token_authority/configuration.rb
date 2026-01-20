# frozen_string_literal: true

module TokenAuthority
  class Configuration
    attr_accessor :audience_url, :authorization_grant_layout, :error_page_layout,
      :issuer_url, :parent_controller, :secret_key, :user_class

    def initialize
      @audience_url = nil
      @authorization_grant_layout = "application"
      @error_page_layout = "application"
      @issuer_url = nil
      @parent_controller = "ApplicationController"
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
