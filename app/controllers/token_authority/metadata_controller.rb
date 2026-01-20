# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for RFC 8414 OAuth 2.0 Authorization Server Metadata
  class MetadataController < ActionController::API
    def show
      metadata = AuthorizationServerMetadata.new(mount_path: params[:mount_path])
      render json: metadata.to_h
    end
  end
end
