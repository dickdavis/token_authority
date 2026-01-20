# frozen_string_literal: true

module TokenAuthority
  ##
  # Controller for RFC 9728 OAuth 2.0 Protected Resource Metadata
  class ResourceMetadataController < ActionController::API
    def show
      metadata = ProtectedResourceMetadata.new(mount_path: params[:mount_path])
      render json: metadata.to_h
    end
  end
end
