# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for granting authorization to clients.
  #
  # Inherits from the controller configured via TokenAuthority.config.authenticatable_controller.
  # The authenticatable controller must implement:
  # - authenticate_user! (before_action that ensures user is logged in)
  # - current_user (returns the currently authenticated user)
  #
  # For Devise users, these methods are already available on ApplicationController.
  # For other authentication systems, implement these methods on your authenticatable controller.
  class AuthorizationGrantsController < TokenAuthority.config.authenticatable_controller.constantize
    layout -> { TokenAuthority.config.consent_page_layout }

    before_action :authenticate_user!
    before_action :set_authorization_request
    before_action :set_token_authority_client

    rescue_from TokenAuthority::InvalidRedirectUrlError do |error|
      session.delete(:token_authority_internal_state)
      render "token_authority/client_error",
        layout: TokenAuthority.config.error_page_layout,
        status: :bad_request,
        locals: {error_class: error.class, error_message: error.message}
    end

    def new
      render :new, locals: {
        client_name: @token_authority_client.name,
        resources: @authorization_request.resources || [],
        scopes: @authorization_request.scope
      }
    end

    def create
      state = @authorization_request.state

      unless ActiveModel::Type::Boolean.new.cast(params[:approve])
        redirect_to_client(params_for_redirect: {error: "access_denied", state:}) and return
      end

      grant = @token_authority_client.new_authorization_grant(
        user: current_user,
        challenge_params: {
          code_challenge: @authorization_request.code_challenge,
          code_challenge_method: @authorization_request.code_challenge_method,
          redirect_uri: @authorization_request.redirect_uri,
          resources: @authorization_request.resources || [],
          scopes: @authorization_request.scope
        }
      )

      redirect_to_client(params_for_redirect: {code: grant.public_id, state:}) and return if grant.persisted?

      redirect_to_client(params_for_redirect: {error: "invalid_request", state:})
    end

    private

    def set_authorization_request
      internal_state = session[:token_authority_internal_state]

      if internal_state.blank?
        render_state_error("Authorization state not found")
        return
      end

      @authorization_request = TokenAuthority::AuthorizationRequest.from_internal_state_token(internal_state)
    rescue JWT::DecodeError, JWT::ExpiredSignature
      clear_internal_state
      render_state_error("Invalid or expired authorization state")
    end

    def set_token_authority_client
      @token_authority_client = @authorization_request.token_authority_client
    end

    def redirect_to_client(params_for_redirect:)
      clear_internal_state
      url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
      redirect_to url, allow_other_host: true
    end

    def clear_internal_state
      session.delete(:token_authority_internal_state)
    end

    def render_state_error(message)
      render "token_authority/client_error",
        layout: TokenAuthority.config.error_page_layout,
        status: :bad_request,
        locals: {error_class: "InvalidStateError", error_message: message}
    end
  end
end
