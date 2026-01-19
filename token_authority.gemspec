require_relative "lib/token_authority/version"

Gem::Specification.new do |spec|
  spec.name = "token_authority"
  spec.version = TokenAuthority::VERSION
  spec.authors = ["Dick Davis"]
  spec.email = ["webmaster@dick.codes"]
  spec.homepage = "https://github.com/dickdavis/token-authority"
  spec.summary = "Rails engine allowing apps to act as their own OAuth 2.1 provider."
  spec.description = "Rails engine allowing apps to act as their own OAuth 2.1 provider."
  spec.license = "MIT"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  end

  spec.add_dependency "rails", ">= 8.1.2"
end
