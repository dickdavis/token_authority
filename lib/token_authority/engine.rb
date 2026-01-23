module TokenAuthority
  class Engine < ::Rails::Engine
    isolate_namespace TokenAuthority

    # Register the event subscriber if configured
    initializer "token_authority.event_logging", after: :load_config_initializers do
      if TokenAuthority.config.event_logging_enabled
        require "token_authority/log_event_subscriber"
        Rails.event.subscribe(TokenAuthority::LogEventSubscriber.new)
      end
    end
  end
end
