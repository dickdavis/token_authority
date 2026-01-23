# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for authorizing an OAuth request.
  class AuthorizationsController < ActionController::Base
    include TokenAuthority::ClientAuthentication

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
        session[:token_authority_internal_state] = authorization_request.to_internal_state_token
        redirect_to new_authorization_grant_path
      elsif authorization_request.errors.where(:redirect_uri).any?
        head :bad_request and return
      elsif authorization_request.errors.where(:resources).any?
        params_for_redirect = {error: :invalid_target, state:}.compact
        url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
        redirect_to url, allow_other_host: true
      elsif authorization_request.errors.where(:scope).any?
        params_for_redirect = {error: :invalid_scope, state:}.compact
        url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
        redirect_to url, allow_other_host: true
      else
        params_for_redirect = {error: :invalid_request, state:}.compact
        url = @token_authority_client.url_for_redirect(params: params_for_redirect.compact)
        redirect_to url, allow_other_host: true
      end
    end
  end
end
