# frozen_string_literal: true

module TokenAuthority
  # Handles OAuth 2.1 authorization requests (GET /authorize).
  #
  # This controller implements the initial step of the authorization code flow.
  # It validates the authorization request parameters, authenticates the client,
  # and redirects to the consent screen if everything is valid.
  #
  # The controller emits structured events for monitoring authorization requests,
  # validation failures, and error conditions. Error responses follow OAuth 2.1
  # specifications, redirecting to the client's redirect_uri when possible.
  #
  # @example Authorization request
  #   GET /authorize?client_id=abc123
  #     &redirect_uri=https://app.example.com/callback
  #     &response_type=code
  #     &state=xyz
  #     &code_challenge=E9Melhoa...
  #     &code_challenge_method=S256
  #     &scope=read+write
  #
  # @since 0.2.0
  class AuthorizationsController < ActionController::Base
    include TokenAuthority::ClientAuthentication
    include TokenAuthority::ControllerEventLogging

    before_action :authenticate_client

    rescue_from TokenAuthority::InvalidRedirectUrlError do |error|
      render "token_authority/client_error",
        layout: TokenAuthority.config.error_page_layout,
        status: :bad_request,
        locals: {error_class: error.class, error_message: error.message}
    end

    def authorize
      state = params[:state]
      resources = Array(params[:resource]).presence || []

      notify_event("authorization.request.received",
        client_id: params[:client_id],
        client_type: @token_authority_client&.client_type,
        redirect_uri: params[:redirect_uri],
        has_pkce: params[:code_challenge].present?,
        requested_scopes: params[:scope],
        requested_resources: resources)

      authorization_request = @token_authority_client.new_authorization_request(
        client_id: params[:client_id],
        code_challenge: params[:code_challenge],
        code_challenge_method: params[:code_challenge_method],
        redirect_uri: params[:redirect_uri],
        response_type: params[:response_type],
        state:,
        resources:,
        scope: params[:scope]
      )

      if authorization_request.valid?
        notify_event("authorization.request.validated",
          client_id: params[:client_id],
          validated_scopes: authorization_request.scope,
          validated_resources: authorization_request.resources)

        session[:token_authority_internal_state] = authorization_request.to_internal_state_token
        redirect_to new_authorization_grant_path
      elsif authorization_request.errors.where(:redirect_uri).any?
        notify_event("authorization.request.failed",
          client_id: params[:client_id],
          error_type: "invalid_redirect_uri",
          validation_errors: authorization_request.errors.full_messages)

        head :bad_request and return
      elsif authorization_request.errors.where(:resources).any?
        notify_event("authorization.request.failed",
          client_id: params[:client_id],
          error_type: "invalid_target",
          validation_errors: authorization_request.errors.full_messages)

        params_for_redirect = {error: :invalid_target, state:}.compact
        url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
        redirect_to url, allow_other_host: true
      elsif authorization_request.errors.where(:scope).any?
        notify_event("authorization.request.failed",
          client_id: params[:client_id],
          error_type: "invalid_scope",
          validation_errors: authorization_request.errors.full_messages)

        params_for_redirect = {error: :invalid_scope, state:}.compact
        url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
        redirect_to url, allow_other_host: true
      else
        notify_event("authorization.request.failed",
          client_id: params[:client_id],
          error_type: "invalid_request",
          validation_errors: authorization_request.errors.full_messages)

        params_for_redirect = {error: :invalid_request, state:}.compact
        url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
        redirect_to url, allow_other_host: true
      end
    end
  end
end
