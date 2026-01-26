## [Unreleased]

## [0.3.1] - 2025-01-25

### Fixed

- Do not expire OAuth sessions when access tokens expire; this was preventing session refresh flow from completing successfully in some cases.

## [0.3.0] - 2025-01-24

### Added

- Added support for multiple protected resources; applications can now define multiple protected resources under different subdomain constraints.
- Added `issuer_url` method that returns either `token_issuer_url` or derives from `authorization_servers`
- Added validation requiring either `token_issuer_url` or `:authorization_servers` on at least one resource

### Breaking

- Replaced `rfc_9728_*` config options with `config.resources` hash (keyed by symbol)
- Replaced `token_authority_routes` with `token_authority_auth_server_routes` and `token_authority_protected_resource_route`
- Removed `rfc_8707_resources` config option; resource allowlist is now derived from `config.resources`
- Renamed `rfc_8707_require_resource` to `require_resource`
- Renamed `rfc_8707_enabled?` method to `resources_enabled?`
- Changed default for `require_scope` from `false` to `true`
- Changed default for `require_resource` from `false` to `true`
- Changed default for `token_audience_url` from application URL to `nil`
- Changed default for `dcr_enabled` from `false` to `true`
- Changed default for `token_issuer_url` from required to `nil`
- When `token_audience_url` is nil, the `:resource` URL is used as the audience claim
- When `token_issuer_url` is nil, it's derived from the first resource's `:authorization_servers`
- Renamed configuration options to remove RFC number prefixes:
  - `rfc_9068_audience_url` → `token_audience_url`
  - `rfc_9068_issuer_url` → `token_issuer_url`
  - `rfc_9068_default_access_token_duration` → `default_access_token_duration`
  - `rfc_9068_default_refresh_token_duration` → `default_refresh_token_duration`
  - `rfc_8414_service_documentation` → `authorization_server_documentation`
  - `rfc_7591_enabled` → `dcr_enabled`
  - `rfc_7591_require_initial_access_token` → `dcr_require_initial_access_token`
  - `rfc_7591_initial_access_token_validator` → `dcr_initial_access_token_validator`
  - `rfc_7591_allowed_grant_types` → `dcr_allowed_grant_types`
  - `rfc_7591_allowed_response_types` → `dcr_allowed_response_types`
  - `rfc_7591_allowed_scopes` → `dcr_allowed_scopes`
  - `rfc_7591_allowed_token_endpoint_auth_methods` → `dcr_allowed_token_endpoint_auth_methods`
  - `rfc_7591_client_secret_expiration` → `dcr_client_secret_expiration`
  - `rfc_7591_software_statement_jwks` → `dcr_software_statement_jwks`
  - `rfc_7591_software_statement_required` → `dcr_software_statement_required`
  - `rfc_7591_jwks_cache_ttl` → `dcr_jwks_cache_ttl`

## [0.2.1] - 2025-01-24

### Fixes

- Implemented support for all mandatory access token JWT claims
- Disable turbo on consent screen to allow redirects

### Documentation

- Update README to include link to MCP Quickstart guide.

## [0.2.0] - 2025-01-23

- Implemented support for OAuth 2.1 authorization flows and JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens (RFC 9068).
- Implemented support for OAuth 2.0 Authorization Server Metadata (RFC 8414).
- Implemented support for OAuth 2.0 Protected Resource Metadata (RFC 9728).
- Implemented support for OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591).
- Implemented support for OAuth Client ID Metadata Documents.
- Implemented support for OAuth 2.0 Resource Indicators (RFC 8707).
- Implemented configuration.
- Implemented install generator with templates.
- Implemented structured event logging.
- Implemented instrumentation.
- Added documentation.

## [0.1.0] - 2026-01-19

- Initial release

[Unreleased]: https://github.com/dickdavis/token_authority/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/dickdavis/token_authority/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dickdavis/token_authority/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dickdavis/token_authority/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dickdavis/token_authority/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dickdavis/token_authority/releases/tag/v0.1.0
