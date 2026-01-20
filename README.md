# TokenAuthority

Rails engine allowing apps to act as their own OAuth 2.1 provider.

## Usage

How to use my plugin.

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
  mount TokenAuthority::Engine => "/oauth"
end
```

This exposes the OAuth endpoints at `/oauth/authorize`, `/oauth/token`, etc.

## Configuration

The generated initializer configures TokenAuthority:

```ruby
TokenAuthority.configure do |config|
  config.audience_url = ENV.fetch("TOKEN_AUTHORITY_AUDIENCE_URL", "http://localhost:3000/api/")
  config.issuer_url = ENV.fetch("TOKEN_AUTHORITY_ISSUER_URL", "http://localhost:3000/")
  config.parent_controller = "ApplicationController"
  config.authorization_grant_layout = "application"
  config.error_page_layout = "application"
  config.secret_key = Rails.application.credentials.secret_key_base
  config.user_class = "User"
end
```

| Option | Description |
|--------|-------------|
| `audience_url` | The audience URL for JWT tokens (used as the `aud` claim) |
| `authorization_grant_layout` | Layout for the OAuth consent screen (default: `"application"`) |
| `error_page_layout` | Layout for error pages like invalid redirect URL (default: `"application"`) |
| `issuer_url` | The issuer URL for JWT tokens (used as the `iss` claim) |
| `parent_controller` | Parent controller for user-facing endpoints (see [User Authentication](#user-authentication)) |
| `secret_key` | Secret key for signing JWTs and generating client secrets |
| `user_class` | Class name of your user model (e.g., `"User"`, `"Account"`) |

## User Authentication

TokenAuthority requires user authentication for the consent screen where users approve or deny OAuth client access. The `parent_controller` configuration specifies which controller provides the authentication methods.

The parent controller must implement two methods:

| Method | Purpose |
|--------|---------|
| `authenticate_user!` | A before_action that ensures the user is logged in (redirects to login if not) |
| `current_user` | Returns the currently authenticated user |

### With Devise

If you use [Devise](https://github.com/heartcombo/devise), these methods are already available on `ApplicationController`. No additional configuration is needed:

```ruby
TokenAuthority.configure do |config|
  config.parent_controller = "ApplicationController"
end
```

### With Other Authentication Systems

For other authentication systems, implement `authenticate_user!` and `current_user` on your parent controller. You can delegate to your existing authentication methods:

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
  config.parent_controller = "OAuthBaseController"
end
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

## Releasing

1. Update the version number in `lib/token_authority/version.rb`
2. Commit the version change: `git commit -am "Bump version to X.Y.Z"`
3. Run the release task: `rake release`

This will create a git tag, push the tag to GitHub, and publish the gem to RubyGems.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dickdavis/token-authority.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
