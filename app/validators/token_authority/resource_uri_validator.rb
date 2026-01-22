# frozen_string_literal: true

module TokenAuthority
  ##
  # Validates resource URIs per RFC 8707 requirements.
  # Resource URIs must be absolute URIs with http/https scheme and no fragments.
  class ResourceUriValidator
    class << self
      # Validates a single resource URI
      # @param uri [String] the URI to validate
      # @return [Boolean] true if valid
      def valid?(uri)
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

      # Validates an array of resource URIs
      # @param resources [Array<String>] the URIs to validate
      # @return [Boolean] true if all are valid
      def valid_all?(resources)
        return true if resources.blank?

        resources.all? { |uri| valid?(uri) }
      end

      # Checks if a resource URI is in the allowed list
      # @param uri [String] the URI to check
      # @return [Boolean] true if allowed (or if no allowlist configured)
      def allowed?(uri)
        allowed_resources = TokenAuthority.config.rfc_8707_allowed_resources
        return true if allowed_resources.nil?

        allowed_resources.include?(uri)
      end

      # Checks if all resources are in the allowed list
      # @param resources [Array<String>] the URIs to check
      # @return [Boolean] true if all allowed (or if no allowlist configured)
      def allowed_all?(resources)
        return true if resources.blank?

        resources.all? { |uri| allowed?(uri) }
      end

      # Checks if requested resources are a subset of granted resources (for downscoping)
      # @param requested [Array<String>] the requested resources
      # @param granted [Array<String>] the originally granted resources
      # @return [Boolean] true if requested is subset of granted (or if granted is empty)
      def subset?(requested, granted)
        return true if granted.blank?
        return true if requested.blank?

        (requested - granted).empty?
      end
    end
  end
end
