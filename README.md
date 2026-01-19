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

Run the install generator to create the required database tables:

```bash
$ bin/rails generate token_authority:install
```

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

This creates the following tables:

- `token_authority_clients` - OAuth client applications
- `token_authority_authorization_grants` - Authorization codes issued during the OAuth flow
- `token_authority_challenges` - PKCE code challenges
- `token_authority_sessions` - Tracks issued tokens and their status

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
