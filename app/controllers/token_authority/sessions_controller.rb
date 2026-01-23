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
        resources:
      )

      if access_token_request.valid?
        access_token, refresh_token, expiration = @authorization_grant.redeem(
          resources: access_token_request.effective_resources
        ).deconstruct
        render json: {access_token:, refresh_token:, token_type: "bearer", expires_in: expiration}
      elsif access_token_request.errors.where(:resources).any?
        render_token_request_error(error: "invalid_target")
      else
        render_token_request_error(error: "invalid_request")
      end
    end

    def refresh
      resources = Array(params[:resource]).presence || []

      token = TokenAuthority::RefreshToken.from_token(params[:refresh_token])
      token_authority_session = TokenAuthority::Session.find_by(refresh_token_jti: token.jti)
      client_id = params[:client_id].presence ||
        token_authority_session.token_authority_authorization_grant.resolved_client.public_id

      # Validate resources for refresh (if provided)
      if resources.any?
        # If resources are provided but feature is disabled, reject
        unless TokenAuthority.config.rfc_8707_enabled?
          render_token_request_error(error: "invalid_target") and return
        end

        granted_resources = token_authority_session.token_authority_authorization_grant
          .token_authority_challenge&.resources || []

        unless TokenAuthority::ResourceUriValidator.valid_all?(resources)
          render_token_request_error(error: "invalid_target") and return
        end

        unless TokenAuthority::ResourceUriValidator.allowed_all?(resources)
          render_token_request_error(error: "invalid_target") and return
        end

        unless TokenAuthority::ResourceUriValidator.subset?(resources, granted_resources)
          render_token_request_error(error: "invalid_target") and return
        end
      end

      # Use requested resources or fall back to granted resources
      effective_resources = resources.any? ? resources :
        (token_authority_session.token_authority_authorization_grant.token_authority_challenge&.resources || [])

      access_token, refresh_token, expiration = token_authority_session.refresh(
        token:,
        client_id:,
        resources: effective_resources
      ).deconstruct

      render json: {access_token:, refresh_token:, token_type: "bearer", expires_in: expiration}
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
