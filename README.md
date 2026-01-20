# TokenAuthority

Rails engine allowing apps to act as their own OAuth 2.1 provider. The goal of this project is to make authorization dead simple for MCP server developers.

This project aims to implement the OAuth standards specified in the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#standards-compliance).

| Status | Standard |
|--------|----------|
| ✅ | [OAuth 2.1 IETF DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) |
| ✅ | [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414) |
| ❌ | [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591) |
| ✅ | [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728) |
| ❌ | [OAuth Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) |

## Usage

TokenAuthority is simple to install and configure. It slots alongside your existing authentication solution easily.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "token_authority"
```

And then execute:
```bash
$ bundle
```

Run the install generator:

```bash
$ bin/rails generate token_authority:install
```

This creates:

1. A migration for the required database tables
2. An initializer at `config/initializers/token_authority.rb`
3. Customizable views at `app/views/token_authority/`

The generator accepts the following options:

| Option | Default | Description |
|--------|---------|-------------|
| `--user_table_name` | `users` | Name of your application's user table |
| `--user_foreign_key_type` | `bigint` | Primary key type of your user table (`bigint`, `uuid`, `integer`) |

For example, if your user table is named `accounts` with UUID primary keys:

```bash
$ bin/rails generate token_authority:install --user_table_name=accounts --user_foreign_key_type=uuid
```

Then run the migration:

```bash
$ bin/rails db:migrate
```

### Database Tables

The migration creates the following tables:

- `token_authority_clients` - OAuth client applications
- `token_authority_authorization_grants` - Authorization codes issued during the OAuth flow
- `token_authority_challenges` - PKCE code challenges
- `token_authority_sessions` - Tracks issued tokens and their status

### Mount the Engine

Add the engine routes to your `config/routes.rb`:

```ruby
Rails.application.routes.draw do
  token_authority_routes
end
```

This exposes:
- RFC 8414 Authorization Server Metadata at `/.well-known/oauth-authorization-server`
- RFC 9728 Protected Resource Metadata at `/.well-known/oauth-protected-resource`
- OAuth endpoints at `/oauth/authorize`, `/oauth/token`, etc.

To mount the engine at a different path, use the `at` option:

```ruby
Rails.application.routes.draw do
  token_authority_routes(at: "/auth")
end
```

## Configuration

The generated initializer configures TokenAuthority:

```ruby
TokenAuthority.configure do |config|
  # General
  config.secret_key = Rails.application.credentials.secret_key_base

  # Token
  config.audience_url = ENV.fetch("TOKEN_AUTHORITY_AUDIENCE_URL", "http://localhost:3000/api/")
  config.issuer_url = ENV.fetch("TOKEN_AUTHORITY_ISSUER_URL", "http://localhost:3000/")
  # config.default_access_token_duration = 300 # 5 minutes
  # config.default_refresh_token_duration = 1_209_600 # 14 days

  # User Authentication
  config.authenticatable_controller = "ApplicationController"
  config.user_class = "User"

  # UI/Layout
  config.consent_page_layout = "application"
  config.error_page_layout = "application"

  # Server Metadata (RFC 8414)
  # config.scopes_supported = ["read", "write"]
  # config.service_documentation = "https://example.com/docs/oauth"
end
```

### General

| Option | Description |
|--------|-------------|
| `secret_key` | Secret key for signing JWTs and generating client secrets |

### Token

| Option | Description |
|--------|-------------|
| `audience_url` | The audience URL for JWT tokens (used as the `aud` claim) |
| `issuer_url` | The issuer URL for JWT tokens (used as the `iss` claim) |
| `default_access_token_duration` | Default duration for access tokens in seconds (default: 300 / 5 minutes) |
| `default_refresh_token_duration` | Default duration for refresh tokens in seconds (default: 1,209,600 / 14 days) |

### User Authentication

| Option | Description |
|--------|-------------|
| `authenticatable_controller` | Controller for user-facing endpoints (see [User Authentication](#user-authentication-1)) |
| `user_class` | Class name of your user model (e.g., `"User"`, `"Account"`) |

### UI/Layout

| Option | Description |
|--------|-------------|
| `consent_page_layout` | Layout for the OAuth consent screen (default: `"application"`) |
| `error_page_layout` | Layout for error pages like invalid redirect URL (default: `"application"`) |

### Server Metadata (RFC 8414)

| Option | Description |
|--------|-------------|
| `scopes_supported` | Array of OAuth scopes your server supports (optional) |
| `service_documentation` | URL to developer documentation (optional) |

### Protected Resource Metadata (RFC 9728)

| Option | Description |
|--------|-------------|
| `resource_url` | The protected resource's identifier URL (defaults to `issuer_url`) |
| `resource_scopes_supported` | Scopes accepted by the resource (falls back to `scopes_supported`) |
| `resource_authorization_servers` | List of authorization server issuer URLs (defaults to local AS) |
| `resource_bearer_methods_supported` | Token presentation methods (e.g., `["header"]`) |
| `resource_jwks_uri` | URL to the resource's JSON Web Key Set |
| `resource_name` | Human-readable name for the resource |
| `resource_documentation` | URL to developer documentation |
| `resource_policy_uri` | URL to the resource's privacy policy |
| `resource_tos_uri` | URL to the resource's terms of service |

## User Authentication

TokenAuthority requires user authentication for the consent screen where users approve or deny OAuth client access. The `authenticatable_controller` configuration specifies which controller provides the authentication methods.

The authenticatable controller must implement two methods:

| Method | Purpose |
|--------|---------|
| `authenticate_user!` | A before_action that ensures the user is logged in (redirects to login if not) |
| `current_user` | Returns the currently authenticated user |

### With Devise

If you use [Devise](https://github.com/heartcombo/devise), these methods are already available on `ApplicationController`. No additional configuration is needed:

```ruby
TokenAuthority.configure do |config|
  config.authenticatable_controller = "ApplicationController"
end
```

### With Other Authentication Systems

For other authentication systems, implement `authenticate_user!` and `current_user` on your authenticatable controller. You can delegate to your existing authentication methods:

```ruby
class ApplicationController < ActionController::Base
  def authenticate_user!
    redirect_to login_path, alert: "Please log in" unless current_user
  end

  def current_user
    @current_user ||= User.find_by(id: session[:user_id])
  end
end
```

Or if your authentication library uses different method names, delegate to them:

```ruby
class ApplicationController < ActionController::Base
  def authenticate_user!
    authenticate_account!  # Your authentication method
  end

  def current_user
    current_account  # Your current user method
  end
end
```

Alternatively, create a dedicated controller with these methods and configure TokenAuthority to use it:

```ruby
# app/controllers/oauth_base_controller.rb
class OAuthBaseController < ApplicationController
  def authenticate_user!
    # Your authentication logic
  end

  def current_user
    # Return the current user
  end
end

# config/initializers/token_authority.rb
TokenAuthority.configure do |config|
  config.authenticatable_controller = "OAuthBaseController"
end
```

## Protecting API Endpoints

TokenAuthority provides the `TokenAuthentication` concern for validating JWT access tokens in your API controllers. Include the concern and use `user_from_token` to authenticate requests:

```ruby
class Api::V1::ResourcesController < ActionController::API
  include TokenAuthority::TokenAuthentication

  def index
    user = user_from_token
    render json: user.resources
  end
end
```

The `user_from_token` method:
1. Extracts the Bearer token from the `Authorization` header
2. Decodes and validates the JWT access token
3. Verifies the associated session is active
4. Returns the authenticated user

### Error Handling

The concern automatically handles authentication errors and returns JSON responses:

| Scenario | HTTP Status | Error Key |
|----------|-------------|-----------|
| Missing or blank `Authorization` header | 401 | `missing_auth_header` |
| Malformed or invalid JWT | 401 | `invalid_token` |
| Expired token or inactive session | 401 | `unauthorized_token` |

Example error response:

```json
{
  "error": "The access token is expired or unauthorized"
}
```

## Customizing Views

The install generator copies TokenAuthority's views to your application at `app/views/token_authority/`. These views are intentionally unstyled so you can customize them to match your application's branding.

### Copied Views

| View | Purpose |
|------|---------|
| `authorization_grants/new.html.erb` | OAuth consent screen where users approve or deny client access |
| `client_error.html.erb` | Error page shown when the OAuth client's redirect URL is invalid |

### Styling the Views

Edit the copied views to add your CSS classes, layout structure, and branding:

```erb
<%# app/views/token_authority/authorization_grants/new.html.erb %>
<div class="oauth-consent">
  <h1>Authorize <%= client_name %></h1>
  <p><%= t("token_authority.authorization_grants.new.lede") %></p>

  <%= form_with url: token_authority.authorization_grants_path, method: :post do |form| %>
    <%= form.hidden_field :state, value: state %>
    <%= form.submit t("token_authority.authorization_grants.new.approve"), name: "approve", value: "true", class: "btn btn-primary" %>
    <%= form.submit t("token_authority.authorization_grants.new.reject"), name: "approve", value: "false", class: "btn btn-secondary" %>
  <% end %>
</div>
```

The views use Rails I18n for text content. You can customize the text by overriding the keys in your locale files. See `config/locales/token_authority.en.yml` in the gem for available keys.

## Development

Clone the repository and install dependencies:

```bash
git clone https://github.com/dickdavis/token-authority.git
cd token-authority
bundle install
```

Set up git hooks:

```bash
bundle exec lefthook install
```

Run the test suite:

```bash
bundle exec rspec
```

Run the linter:

```bash
bundle exec standardrb
```

### Manual Testing with the Dummy App

The `spec/dummy` directory contains a Rails application for testing the engine. The dummy app includes a `/callback` endpoint that displays authorization codes returned from the OAuth flow, and helper scripts that guide you through the complete OAuth flow.

1. Start the dummy app server:

```bash
cd spec/dummy
bin/rails db:migrate
bin/rails server
```

2. Create a test user and client in the Rails console:

```bash
bin/rails console
```

```ruby
# Create a test user
User.create!(email: "test@example.com", password: "password")

# Create a test client
TokenAuthority::Client.create!(
  name: "Test Client",
  client_type: "confidential",
  redirect_uri: "http://localhost:3000/callback",
  access_token_duration: 3600,
  refresh_token_duration: 86400
)
```

3. Run one of the helper scripts to test the OAuth flow:

```bash
bin/rails runner script/generate_link_for_authorize_endpoint.rb
```

The script will display an authorization URL. Open it in your browser, sign in with the test user, and approve the authorization. After being redirected to the callback page, copy the authorization code and enter it into the script prompt. The script will output a curl command to exchange the code for tokens.

Available scripts:

| Script | Description |
|--------|-------------|
| `generate_link_for_authorize_endpoint.rb` | Confidential client with PKCE |
| `generate_link_for_authorize_endpoint_confidential.rb` | Confidential client without PKCE |
| `generate_link_for_authorize_endpoint_confidential_pkce.rb` | Confidential client with PKCE and redirect_uri |
| `generate_link_for_authorize_endpoint_public.rb` | Public client with PKCE |

## Releasing

1. Update the version number in `lib/token_authority/version.rb`
2. Commit the version change: `git commit -am "Bump version to X.Y.Z"`
3. Run the release task: `rake release`

This will create a git tag, push the tag to GitHub, and publish the gem to RubyGems.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dickdavis/token-authority.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
