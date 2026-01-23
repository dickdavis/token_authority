# frozen_string_literal: true

module TokenAuthority
  ##
  # Provides resource handling behavior for models that have resources.
  # Handles RFC 8707 resource indicator validation and subset checking.
  module Resourceable
    extend ActiveSupport::Concern

    def resources
      @resources ||= []
    end

    def resources=(value)
      @resources = Array(value).presence || []
    end

    private

    def valid_resource_uri?(uri)
      return false if uri.blank?

      parsed_uri = URI.parse(uri)

      # Must be absolute URI with http/https scheme
      return false unless parsed_uri.is_a?(URI::HTTP) || parsed_uri.is_a?(URI::HTTPS)

      # Must not have a fragment
      return false if parsed_uri.fragment.present?

      # Must have a host
      return false if parsed_uri.host.blank?

      true
    rescue URI::InvalidURIError
      false
    end

    def valid_resource_uris?
      resources.all? { |uri| valid_resource_uri?(uri) }
    end

    def allowed_resources?
      return true unless TokenAuthority.config.rfc_8707_enabled?

      resources.all? { |uri| TokenAuthority.config.rfc_8707_resources.key?(uri) }
    end

    def resources_subset_of?(granted)
      return true if granted.blank? || resources.blank?

      (resources - granted).empty?
    end
  end
end
