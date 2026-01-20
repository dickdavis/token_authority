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

## Installation

Add this line to your application's Gemfile:

```ruby
gem "token_authority"
```

Run bundle and the install generator:

```bash
$ bundle
$ bin/rails generate token_authority:install
$ bin/rails db:migrate
```

See the [Installation Guide](https://github.com/dickdavis/token_authority/wiki/Installation-Guide) for generator options and custom configurations.

## Configuration

Configure TokenAuthority in the generated initializer:

```ruby
# config/initializers/token_authority.rb
TokenAuthority.configure do |config|
  config.secret_key = Rails.application.credentials.secret_key_base
  config.audience_url = "https://example.com/api/"
  config.issuer_url = "https://example.com/"
  config.authenticatable_controller = "ApplicationController"
  config.user_class = "User"
end
```

See the [Configuration Reference](https://github.com/dickdavis/token_authority/wiki/Configuration-Reference) for all available options.

## Mount the Engine

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

## User Consent

Before issuing authorization codes, TokenAuthority displays a consent screen where users can approve or deny access to OAuth clients. The consent views are fully customizable and the layout is configurable—see [Customizing Views](https://github.com/dickdavis/token_authority/wiki/Customizing-Views) for details.

The consent screen requires user authentication. Your `authenticatable_controller` must provide two methods:

- `authenticate_user!` - Ensures the user is logged in (redirects to login if not)
- `current_user` - Returns the authenticated user

If you use [Devise](https://github.com/heartcombo/devise), these methods are already available on `ApplicationController`. For other authentication systems, see [User Authentication](https://github.com/dickdavis/token_authority/wiki/User-Authentication).

## Protecting API Endpoints

Use the `TokenAuthentication` concern to validate access tokens:

```ruby
class Api::V1::ResourcesController < ActionController::API
  include TokenAuthority::TokenAuthentication

  def index
    user = user_from_token
    render json: user.resources
  end
end
```

See [Protecting API Endpoints](https://github.com/dickdavis/token_authority/wiki/Protecting-API-Endpoints) for error handling details.

## Learn More

- [Installation Guide](https://github.com/dickdavis/token_authority/wiki/Installation-Guide) - Generator options, custom table names
- [Configuration Reference](https://github.com/dickdavis/token_authority/wiki/Configuration-Reference) - All configuration options
- [User Authentication](https://github.com/dickdavis/token_authority/wiki/User-Authentication) - Custom authentication setups
- [Protecting API Endpoints](https://github.com/dickdavis/token_authority/wiki/Protecting-API-Endpoints) - Error handling, validation details
- [Customizing Views](https://github.com/dickdavis/token_authority/wiki/Customizing-Views) - Styling consent screens

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
  redirect_uri: "http://localhost:3000/callback"
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
