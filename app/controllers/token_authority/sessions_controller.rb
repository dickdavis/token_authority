# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for issuing access and refresh tokens.
  class SessionsController < ActionController::API
    include TokenAuthority::ClientAuthentication
    include TokenAuthority::ControllerEventLogging

    before_action :set_authorization_grant, only: :token
    before_action :authenticate_client, except: :unsupported_grant_type

    rescue_from TokenAuthority::InvalidGrantError do
      notify_event("token.exchange.failed",
        client_id: params[:client_id],
        error_type: "invalid_grant",
        validation_errors: ["Authorization grant is invalid or expired"])

      render_token_request_error(error: "invalid_grant")
    end

    rescue_from TokenAuthority::ServerError do |error|
      Rails.logger.error(error.message)
      render_token_request_error(error: "server_error", status: :internal_server_error)
    end

    def token
      resources = Array(params[:resource]).presence || []

      notify_event("token.exchange.requested",
        client_id: params[:client_id],
        grant_id: @authorization_grant&.public_id,
        has_code_verifier: params[:code_verifier].present?)

      access_token_request = TokenAuthority::AccessTokenRequest.new(
        token_authority_authorization_grant: @authorization_grant,
        code_verifier: params[:code_verifier],
        redirect_uri: params[:redirect_uri],
        resources:,
        scope: params[:scope]
      )

      if access_token_request.valid?
        access_token, refresh_token, expiration, scope, token_authority_session = @authorization_grant.redeem(
          resources: access_token_request.effective_resources,
          scopes: access_token_request.effective_scopes
        ).deconstruct

        notify_event("token.exchange.completed",
          client_id: params[:client_id],
          session_id: token_authority_session&.id,
          access_token_expires_in: expiration)

        response_body = {access_token:, refresh_token:, token_type: "bearer", expires_in: expiration, scope:}.compact
        render json: response_body
      elsif access_token_request.errors.where(:resources).any?
        notify_event("token.exchange.failed",
          client_id: params[:client_id],
          error_type: "invalid_target",
          validation_errors: access_token_request.errors.full_messages)

        render_token_request_error(error: "invalid_target")
      elsif access_token_request.errors.where(:scope).any?
        notify_event("token.exchange.failed",
          client_id: params[:client_id],
          error_type: "invalid_scope",
          validation_errors: access_token_request.errors.full_messages)

        render_token_request_error(error: "invalid_scope")
      else
        notify_event("token.exchange.failed",
          client_id: params[:client_id],
          error_type: "invalid_request",
          validation_errors: access_token_request.errors.full_messages)

        render_token_request_error(error: "invalid_request")
      end
    end

    def refresh
      token = TokenAuthority::RefreshToken.from_token(params[:refresh_token])
      resources = Array(params[:resource]).presence || []

      refresh_token_request = TokenAuthority::RefreshTokenRequest.new(
        token:,
        client_id: params[:client_id],
        resources:,
        scope: params[:scope]
      )

      old_session = refresh_token_request.token_authority_session

      notify_event("token.refresh.requested",
        client_id: params[:client_id],
        session_id: old_session&.id)

      if refresh_token_request.valid?
        access_token, refresh_token, expiration, scope, new_session = old_session.refresh(
          token:,
          client_id: refresh_token_request.resolved_client_id,
          resources: refresh_token_request.effective_resources,
          scopes: refresh_token_request.effective_scopes
        ).deconstruct

        notify_event("token.refresh.completed",
          client_id: params[:client_id],
          old_session_id: old_session&.id,
          new_session_id: new_session&.id)

        response_body = {access_token:, refresh_token:, token_type: "bearer", expires_in: expiration, scope:}.compact
        render json: response_body
      elsif refresh_token_request.errors.where(:resources).any?
        notify_event("token.refresh.failed",
          client_id: params[:client_id],
          error_type: "invalid_target",
          validation_errors: refresh_token_request.errors.full_messages)

        render_token_request_error(error: "invalid_target")
      elsif refresh_token_request.errors.where(:scope).any?
        notify_event("token.refresh.failed",
          client_id: params[:client_id],
          error_type: "invalid_scope",
          validation_errors: refresh_token_request.errors.full_messages)

        render_token_request_error(error: "invalid_scope")
      else
        notify_event("token.refresh.failed",
          client_id: params[:client_id],
          error_type: "invalid_request",
          validation_errors: refresh_token_request.errors.full_messages)

        render_token_request_error(error: "invalid_request")
      end
    rescue JWT::DecodeError
      notify_event("token.refresh.failed",
        client_id: params[:client_id],
        error_type: "invalid_request",
        validation_errors: ["Invalid refresh token format"])

      render_token_request_error(error: "invalid_request")
    rescue TokenAuthority::RevokedSessionError => error
      notify_event("security.token.theft_detected",
        client_id: error.client_id,
        refreshed_session_id: error.refreshed_session_id,
        revoked_session_id: error.revoked_session_id)

      Rails.logger.warn(error.message)
      render_token_request_error(error: "invalid_request")
    end

    def unsupported_grant_type
      render_token_request_error(error: "unsupported_grant_type")
    end

    def revoke
      notify_event("token.revocation.requested",
        client_id: @token_authority_client&.public_id,
        token_type_hint: params[:token_type_hint])

      token = TokenAuthority::JsonWebToken.decode(params[:token])
      token_authority_session = TokenAuthority::Session.find_by(access_token_jti: token[:jti]) ||
        TokenAuthority::Session.find_by(refresh_token_jti: token[:jti])

      TokenAuthority::Session.revoke_for_token(jti: token[:jti])

      notify_event("token.revocation.completed",
        client_id: @token_authority_client&.public_id,
        session_id: token_authority_session&.id)

      head :ok
    rescue JWT::DecodeError
      render_unsupported_token_type_error
    end

    def revoke_access_token
      notify_event("token.revocation.requested",
        client_id: @token_authority_client&.public_id,
        token_type_hint: "access_token")

      token = TokenAuthority::AccessToken.from_token(params[:token])
      token_authority_session = TokenAuthority::Session.find_by(access_token_jti: token.jti)

      TokenAuthority::Session.revoke_for_access_token(access_token_jti: token.jti)

      notify_event("token.revocation.completed",
        client_id: @token_authority_client&.public_id,
        session_id: token_authority_session&.id)

      head :ok
    rescue JWT::DecodeError
      render_unsupported_token_type_error
    end

    def revoke_refresh_token
      notify_event("token.revocation.requested",
        client_id: @token_authority_client&.public_id,
        token_type_hint: "refresh_token")

      token = TokenAuthority::RefreshToken.from_token(params[:token])
      token_authority_session = TokenAuthority::Session.find_by(refresh_token_jti: token.jti)

      TokenAuthority::Session.revoke_for_refresh_token(refresh_token_jti: token.jti)

      notify_event("token.revocation.completed",
        client_id: @token_authority_client&.public_id,
        session_id: token_authority_session&.id)

      head :ok
    rescue JWT::DecodeError
      render_unsupported_token_type_error
    end

    private

    def set_authorization_grant
      @authorization_grant = TokenAuthority::AuthorizationGrant.find_by(public_id: params[:code])
      raise TokenAuthority::InvalidGrantError if @authorization_grant.blank? || @authorization_grant.redeemed?
    end

    def render_token_request_error(error:, status: :bad_request)
      render json: {error:}, status:
    end

    def render_unsupported_token_type_error
      render json: {error: "unsupported_token_type"}, status: :bad_request
    end
  end
end
