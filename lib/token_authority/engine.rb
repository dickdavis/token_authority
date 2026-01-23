module TokenAuthority
  # Rails engine that integrates TokenAuthority into host applications.
  #
  # The engine uses an isolated namespace to avoid conflicts with the host application's
  # models and controllers. It sets up initializers for event logging and instrumentation
  # based on the configuration settings.
  #
  # @note This engine is automatically loaded when the TokenAuthority gem is required
  #   in a Rails application.
  #
  # @since 0.2.0
  class Engine < ::Rails::Engine
    isolate_namespace TokenAuthority

    # Registers the event subscriber to capture and log OAuth flow events.
    # Only runs if event_logging_enabled is true in the configuration.
    #
    # Events are published through Rails.event and include authorization grants,
    # token exchanges, and security-related activities.
    initializer "token_authority.event_logging", after: :load_config_initializers do
      if TokenAuthority.config.event_logging_enabled
        require "token_authority/log_event_subscriber"
        Rails.event.subscribe(TokenAuthority::LogEventSubscriber.new)
      end
    end

    # Attaches the instrumentation log subscriber to capture performance metrics.
    # Only runs if instrumentation_enabled is true in the configuration.
    #
    # Instrumentation uses ActiveSupport::Notifications to track timing and
    # performance of key operations like JWT encoding/decoding and session creation.
    initializer "token_authority.instrumentation", after: :load_config_initializers do
      if TokenAuthority.config.instrumentation_enabled
        require "token_authority/instrumentation_log_subscriber"
        TokenAuthority::InstrumentationLogSubscriber.subscribe!
      end
    end
  end
end
