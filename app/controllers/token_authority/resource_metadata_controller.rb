# frozen_string_literal: true

module TokenAuthority
  ##
  # Serves RFC 9728 Protected Resource Metadata at /.well-known/oauth-protected-resource
  #
  # This controller enables OAuth clients to discover metadata about protected resources
  # without requiring manual configuration. Clients can query this endpoint to learn:
  # - Which authorization servers issue tokens for this resource
  # - What scopes are supported
  # - How to present bearer tokens (header vs body)
  # - Where to find public keys for token verification
  #
  # The subdomain extraction strategy supports multi-tenant deployments where different
  # subdomains represent different protected resources (e.g., api.example.com vs
  # mcp.example.com). Returns 404 if no configuration exists for the subdomain.
  #
  # @see https://www.rfc-editor.org/rfc/rfc9728.html RFC 9728
  # @since 0.3.0
  class ResourceMetadataController < ActionController::API
    # Returns metadata for the protected resource identified by request subdomain.
    #
    # The subdomain is extracted from the request and used to look up configuration.
    # For requests without a subdomain (bare domain), uses the default protected_resource
    # configuration if present. This allows both single-resource and multi-resource
    # deployments with the same code.
    #
    # @return [JSON] RFC 9728 compliant metadata response
    # @return [HTTP 404] if no configuration exists for this subdomain
    def show
      metadata = ProtectedResourceMetadata.new(resource: request.subdomain)
      render json: metadata.to_h
    rescue ResourceNotConfiguredError
      # Return 404 rather than 500 because this is a client error: they're querying
      # a subdomain that hasn't been configured as a protected resource
      head :not_found
    end
  end
end
