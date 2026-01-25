## [Unreleased]

### Breaking

- Replaced `rfc_9728_*` config options with `config.resources` hash (keyed by symbol)
- Replaced `token_authority_routes` with `token_authority_auth_server_routes` and `token_authority_protected_resource_route`
- Removed `rfc_8707_resources` config option; resource allowlist is now derived from `config.resources`
- Renamed `rfc_8707_require_resource` to `require_resource`
- Renamed `rfc_8707_enabled?` method to `resources_enabled?`

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

[Unreleased]: https://github.com/dickdavis/token_authority/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/dickdavis/token_authority/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dickdavis/token_authority/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dickdavis/token_authority/releases/tag/v0.1.0
