# frozen_string_literal: true

module TokenAuthority
  ##
  # Concern for authenticating users via JWT access tokens.
  module TokenAuthentication
    extend ActiveSupport::Concern

    included do
      include TokenAuthority::ControllerEventLogging

      before_action :decode_token

      rescue_from TokenAuthority::MissingAuthorizationHeaderError, with: :missing_auth_header_response
      rescue_from TokenAuthority::InvalidAccessTokenError, with: :invalid_token_response
      rescue_from TokenAuthority::UnauthorizedAccessTokenError, with: :unauthorized_token_response
    end

    private

    def decode_token
      bearer_token_header = request.headers["AUTHORIZATION"]
      raise TokenAuthority::MissingAuthorizationHeaderError if bearer_token_header.blank?

      token = bearer_token_header.split.last
      access_token = TokenAuthority::AccessToken.from_token(token)

      oauth_session = TokenAuthority::Session.find_by(access_token_jti: access_token.jti)
      raise TokenAuthority::UnauthorizedAccessTokenError if oauth_session.blank?
      raise TokenAuthority::UnauthorizedAccessTokenError unless oauth_session.created_status?
      raise TokenAuthority::UnauthorizedAccessTokenError unless access_token.valid?

      @decoded_token = access_token

      notify_event("authentication.token.succeeded",
        session_id: oauth_session.id,
        token_scopes: access_token.scope)
    rescue JWT::DecodeError, ActiveModel::UnknownAttributeError
      raise TokenAuthority::InvalidAccessTokenError
    end

    def token_user
      @token_user ||= TokenAuthority.config.user_class.constantize.find(@decoded_token.user_id)
    end

    def token_scope
      @token_scope ||= @decoded_token.scope&.split || []
    end

    def missing_auth_header_response
      notify_event("authentication.token.failed",
        failure_reason: "missing_authorization_header")

      render json: {error: I18n.t("token_authority.errors.missing_auth_header")}, status: :unauthorized
    end

    def invalid_token_response
      notify_event("authentication.token.failed",
        failure_reason: "invalid_token_format")

      render json: {error: I18n.t("token_authority.errors.invalid_token")}, status: :unauthorized
    end

    def unauthorized_token_response
      notify_event("authentication.token.failed",
        failure_reason: "unauthorized_token")

      render json: {error: I18n.t("token_authority.errors.unauthorized_token")}, status: :unauthorized
    end
  end
end
