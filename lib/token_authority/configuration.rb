# frozen_string_literal: true

module TokenAuthority
  class Configuration
    attr_accessor :audience_url, :issuer_url, :parent_controller, :secret_key, :user_class

    def initialize
      @audience_url = nil
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
