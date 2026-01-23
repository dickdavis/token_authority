# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for issuing access and refresh tokens.
  class SessionsController < ActionController::API
    include TokenAuthority::ClientAuthentication

    before_action :set_authorization_grant, only: :token
    before_action :authenticate_client, except: :unsupported_grant_type

    rescue_from TokenAuthority::InvalidGrantError do
      render_token_request_error(error: "invalid_grant")
    end

    rescue_from TokenAuthority::ServerError do |error|
      Rails.logger.error(error.message)
      render_token_request_error(error: "server_error", status: :internal_server_error)
    end

    def token
      resources = Array(params[:resource]).presence || []

      access_token_request = TokenAuthority::AccessTokenRequest.new(
        token_authority_authorization_grant: @authorization_grant,
        code_verifier: params[:code_verifier],
        redirect_uri: params[:redirect_uri],
        resources:,
        scope: params[:scope]
      )

      if access_token_request.valid?
        access_token, refresh_token, expiration, scope = @authorization_grant.redeem(
          resources: access_token_request.effective_resources,
          scopes: access_token_request.effective_scopes
        ).deconstruct
        response_body = {access_token:, refresh_token:, token_type: "bearer", expires_in: expiration, scope:}.compact
        render json: response_body
      elsif access_token_request.errors.where(:resources).any?
        render_token_request_error(error: "invalid_target")
      elsif access_token_request.errors.where(:scope).any?
        render_token_request_error(error: "invalid_scope")
      else
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

      if refresh_token_request.valid?
        access_token, refresh_token, expiration, scope = refresh_token_request.token_authority_session.refresh(
          token:,
          client_id: refresh_token_request.resolved_client_id,
          resources: refresh_token_request.effective_resources,
          scopes: refresh_token_request.effective_scopes
        ).deconstruct
        response_body = {access_token:, refresh_token:, token_type: "bearer", expires_in: expiration, scope:}.compact
        render json: response_body
      elsif refresh_token_request.errors.where(:resources).any?
        render_token_request_error(error: "invalid_target")
      elsif refresh_token_request.errors.where(:scope).any?
        render_token_request_error(error: "invalid_scope")
      else
        render_token_request_error(error: "invalid_request")
      end
    rescue JWT::DecodeError
      render_token_request_error(error: "invalid_request")
    rescue TokenAuthority::RevokedSessionError => error
      Rails.logger.warn(error.message)
      render_token_request_error(error: "invalid_request")
    end

    def unsupported_grant_type
      render_token_request_error(error: "unsupported_grant_type")
    end

    def revoke
      token = TokenAuthority::JsonWebToken.decode(params[:token])
      TokenAuthority::Session.revoke_for_token(jti: token[:jti])

      head :ok
    rescue JWT::DecodeError
      render_unsupported_token_type_error
    end

    def revoke_access_token
      token = TokenAuthority::AccessToken.from_token(params[:token])
      TokenAuthority::Session.revoke_for_access_token(access_token_jti: token.jti)

      head :ok
    rescue JWT::DecodeError
      render_unsupported_token_type_error
    end

    def revoke_refresh_token
      token = TokenAuthority::RefreshToken.from_token(params[:token])
      TokenAuthority::Session.revoke_for_refresh_token(refresh_token_jti: token.jti)

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
