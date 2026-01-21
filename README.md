# TokenAuthority

Rails engine allowing apps to act as their own OAuth 2.1 provider. The goal of this project is to make authorization dead simple for MCP server developers.

This project aims to implement the OAuth standards specified in the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#standards-compliance).

| Status | Standard |
|--------|----------|
| ✅ | [OAuth 2.1 IETF DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) |
| ✅ | [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414) |
| ✅ | [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens (RFC 9068)](https://datatracker.ietf.org/doc/html/rfc9068) |
| ✅ | [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591) |
| ✅ | [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728) |
| ✅ | [OAuth Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) |

## Usage

TokenAuthority is simple to install and configure.

### Installation

Add this line to your application's Gemfile:

```ruby
gem "token_authority"
```

Install the gem, generate the required set-up files, and run the migration:

```bash
$ bundle
$ bin/rails generate token_authority:install
$ bin/rails db:migrate
```

See the [Installation Guide](https://github.com/dickdavis/token_authority/wiki/Installation-Guide) for generator options and custom configurations.

### Configuration

Configure TokenAuthority in the generated initializer. The following represents a minimal configuration:

```ruby
# config/initializers/token_authority.rb
TokenAuthority.configure do |config|
  # The secret key used for encryption/decryption
  config.secret_key = Rails.application.credentials.secret_key_base
  # The model that represents a user in the application
  config.user_class = "User"
  # The base controller with authentication methods to inherit from
  config.authenticatable_controller = "ApplicationController"
  # The URI for the protected resource (to be included in tokens and metadata)
  config.rfc_9068_audience_url = "https://example.com/api/"
  # The URI for the authorization server (to be included in tokens and metadata)
  config.rfc_9068_issuer_url = "https://example.com/"
end
```

See the [Configuration Reference](https://github.com/dickdavis/token_authority/wiki/Configuration-Reference) for all available options.

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

### User Consent

Before issuing authorization codes, TokenAuthority displays a consent screen where users can approve or deny access to OAuth clients. The consent views are fully customizable and the layout is configurable—see [Customizing Views](https://github.com/dickdavis/token_authority/wiki/Customizing-Views) for details.

The consent screen requires user authentication. Your `authenticatable_controller` must provide two methods:

- `authenticate_user!` - Ensures the user is logged in (redirects to login if not)
- `current_user` - Returns the authenticated user

If you use [Devise](https://github.com/heartcombo/devise), these methods are already available on `ApplicationController`. For other authentication systems, see [User Authentication](https://github.com/dickdavis/token_authority/wiki/User-Authentication).

### Protecting API Endpoints

Use the `TokenAuthentication` concern to validate access tokens:

```ruby
class Api::V1::ResourcesController < ActionController::API
  include TokenAuthority::TokenAuthentication

  def index
    user = user_from_token # Retrieve the user associated with the access token
    render json: user.resources
  end
end
```

See [Protecting API Endpoints](https://github.com/dickdavis/token_authority/wiki/Protecting-API-Endpoints) for error handling details.

### Learn More

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

For manual testing with the dummy app, see [Manual Testing](https://github.com/dickdavis/token_authority/wiki/Manual-Testing).

### Releasing

1. Update the version number in `lib/token_authority/version.rb`
2. Commit the version change: `git commit -am "Bump version to X.Y.Z"`
3. Run the release task: `rake release`

This will create a git tag, push the tag to GitHub, and publish the gem to RubyGems.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dickdavis/token-authority.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
