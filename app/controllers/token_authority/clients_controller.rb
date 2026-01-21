# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for dynamic client registration (RFC 7591)
  class ClientsController < ActionController::API
    include TokenAuthority::InitialAccessTokenAuthentication

    rescue_from TokenAuthority::InvalidClientMetadataError do |error|
      render_registration_error("invalid_client_metadata", error.message)
    end

    rescue_from TokenAuthority::InvalidSoftwareStatementError do |error|
      render_registration_error("invalid_software_statement", error.message)
    end

    rescue_from TokenAuthority::UnapprovedSoftwareStatementError do |error|
      render_registration_error("unapproved_software_statement", error.message)
    end

    rescue_from TokenAuthority::InvalidInitialAccessTokenError do
      render_registration_error("invalid_token", "Initial access token is invalid or missing", status: :unauthorized)
    end

    rescue_from ActiveRecord::RecordInvalid do |error|
      render_registration_error("invalid_client_metadata", error.record.errors.full_messages.join(", "))
    end

    def create
      request = ClientRegistrationRequest.new(registration_params)

      if request.valid?
        client = request.create_client!
        render json: ClientRegistrationResponse.new(client:).to_h, status: :created
      else
        render_registration_error("invalid_client_metadata", request.errors.full_messages.join(", "))
      end
    end

    private

    def registration_params
      params.permit(
        :token_endpoint_auth_method,
        :client_name,
        :client_uri,
        :logo_uri,
        :tos_uri,
        :policy_uri,
        :scope,
        :jwks_uri,
        :software_id,
        :software_version,
        :software_statement,
        redirect_uris: [],
        grant_types: [],
        response_types: [],
        contacts: [],
        jwks: {}
      )
    end

    def render_registration_error(error, error_description, status: :bad_request)
      render json: {error:, error_description:}, status:
    end
  end
end
