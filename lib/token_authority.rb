require "token_authority/version"
require "token_authority/engine"
require "token_authority/configuration"
require "token_authority/errors"
require "token_authority/instrumentation"
require "token_authority/json_web_token"
require "token_authority/routing/constraints"
require "token_authority/routing/routes"

# TokenAuthority is a Rails engine that enables Rails applications to act as their own
# OAuth 2.1 provider. It provides a complete implementation of the OAuth 2.1 authorization
# framework with support for PKCE, JWT access tokens (RFC 9068), dynamic client registration
# (RFC 7591), resource indicators (RFC 8707), and client metadata documents.
#
# The engine is designed to integrate alongside existing authentication systems (Devise,
# custom auth, etc.) and provides mountable OAuth endpoints for authorization, token
# exchange, and token management.
#
# @example Basic configuration
#   TokenAuthority.configure do |config|
#     config.secret_key = Rails.application.credentials.secret_key_base
#     config.rfc_9068_audience_url = "https://api.example.com"
#     config.rfc_9068_issuer_url = "https://example.com"
#   end
#
# @since 0.2.0
module TokenAuthority
  # Returns the table name prefix for all TokenAuthority models.
  # This ensures that all database tables are namespaced with 'token_authority_'.
  #
  # @return [String] the table name prefix
  def self.table_name_prefix
    "token_authority_"
  end
end
