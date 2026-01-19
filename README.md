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
