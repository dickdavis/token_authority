# frozen_string_literal: true

# Script to register a client using a software statement (signed JWT with client metadata).
# Software statements allow pre-approved client metadata to be distributed securely.
#
# Usage:
#   rails runner script/register_client_with_software_statement.rb

require "net/http"
require "json"
require "uri"
require "openssl"
require "jwt"

# Generate a key pair for signing software statements
# In production, this would be the software publisher's key
puts "Generating RSA key pair for software publisher..."
publisher_key = OpenSSL::PKey::RSA.generate(2048)
publisher_kid = "software-publisher-key-1"

# Create JWKS for the software publisher (authorization server needs this to verify)
publisher_jwks = {
  keys: [
    {
      kty: "RSA",
      kid: publisher_kid,
      use: "sig",
      alg: "RS256",
      n: Base64.urlsafe_encode64(publisher_key.n.to_s(2), padding: false),
      e: Base64.urlsafe_encode64(publisher_key.e.to_s(2), padding: false)
    }
  ]
}

# Configure TokenAuthority to trust this software publisher
TokenAuthority.config.rfc_7591_enabled = true
TokenAuthority.config.rfc_7591_software_statement_jwks = JWT::JWK::Set.new(publisher_jwks)

puts "Configured software statement verification with publisher JWKS.\n\n"

base_url = "http://localhost:3000"
register_url = "#{base_url}/oauth/register"

# Create a software statement (signed JWT with client metadata)
software_statement_payload = {
  # Standard JWT claims
  iss: "https://software-publisher.example.com",
  iat: Time.now.to_i,
  exp: Time.now.to_i + 86400, # Valid for 24 hours

  # Client metadata claims (these take precedence over registration request)
  software_id: "certified-app-12345",
  software_version: "2.0.0",
  client_name: "Certified Application (from software statement)",
  client_uri: "https://certified-app.example.com",
  logo_uri: "https://certified-app.example.com/logo.png",
  tos_uri: "https://certified-app.example.com/tos",
  policy_uri: "https://certified-app.example.com/privacy",
  redirect_uris: ["https://certified-app.example.com/callback"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "client_secret_basic",
  contacts: ["security@certified-app.example.com"]
}

software_statement = JWT.encode(
  software_statement_payload,
  publisher_key,
  "RS256",
  {kid: publisher_kid, typ: "JWT"}
)

# Registration request - can override some claims or just provide the statement
registration_payload = {
  software_statement: software_statement,
  # These will be OVERRIDDEN by software statement claims:
  client_name: "This name will be ignored",
  redirect_uris: ["http://ignored.example.com/callback"]
}

puts "=" * 70
puts "RFC 7591 Dynamic Client Registration - Software Statement"
puts "=" * 70
puts
puts "A software statement is a signed JWT containing client metadata."
puts "Claims in the software statement take PRECEDENCE over claims in"
puts "the registration request (per RFC 7591 Section 2.3)."
puts
puts "Registration endpoint: #{register_url}"
puts
puts "-" * 70
puts "Software Statement JWT:"
puts "-" * 70
puts software_statement
puts
puts "-" * 70
puts "Software Statement Payload (decoded):"
puts "-" * 70
puts JSON.pretty_generate(software_statement_payload)
puts
puts "-" * 70
puts "Registration Request:"
puts "-" * 70
puts JSON.pretty_generate(registration_payload)
puts
puts "Note: client_name and redirect_uris in the request will be overridden"
puts "      by the values in the software statement."
puts
puts "-" * 70
puts "Equivalent curl command:"
puts "-" * 70
puts <<~CURL
  curl -X POST #{register_url} \\
    -H "Content-Type: application/json" \\
    -d '#{registration_payload.to_json}'
CURL
puts
puts "-" * 70
puts "Sending registration request..."
puts "-" * 70

uri = URI.parse(register_url)
http = Net::HTTP.new(uri.host, uri.port)

request = Net::HTTP::Post.new(uri.path)
request["Content-Type"] = "application/json"
request.body = registration_payload.to_json

response = http.request(request)
body = JSON.parse(response.body)

puts
puts "Response status: #{response.code}"
puts "Response body:"
puts JSON.pretty_generate(body)

if response.code == "201"
  client_id = body["client_id"]
  client_secret = body["client_secret"]

  puts
  puts "=" * 70
  puts "SUCCESS! Client registered from software statement."
  puts "=" * 70
  puts
  puts "Client ID:        #{client_id}"
  puts "Client Secret:    #{client_secret}"
  puts "Client Name:      #{body["client_name"]} (from software statement)"
  puts "Software ID:      #{body["software_id"]}"
  puts "Software Version: #{body["software_version"]}"
  puts "Redirect URIs:    #{body["redirect_uris"]} (from software statement)"
  puts
  puts "Notice that the values came from the software statement, not the"
  puts "registration request parameters."
else
  puts
  puts "=" * 70
  puts "FAILED! Registration error."
  puts "=" * 70
  puts
  puts "Error: #{body["error"]}"
  puts "Description: #{body["error_description"]}"
end

# Reset configuration
TokenAuthority.config.rfc_7591_software_statement_jwks = nil
puts
puts "(Configuration reset)"
