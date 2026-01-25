# frozen_string_literal: true

# Script to register a client when initial access token protection is enabled.
# This demonstrates protected registration where clients must present a valid
# initial access token to register.
#
# Usage:
#   rails runner script/register_client_with_initial_access_token.rb

require "net/http"
require "json"
require "uri"

# Configure protected registration
TokenAuthority.config.dcr_enabled = true
TokenAuthority.config.dcr_require_initial_access_token = true
TokenAuthority.config.dcr_initial_access_token_validator = ->(token) {
  # In production, validate against your token store/database
  # This example accepts a specific token for demonstration
  token == "my-secret-initial-access-token-12345"
}

puts "Configured protected registration (requires initial access token).\n\n"

base_url = "http://localhost:3000"
register_url = "#{base_url}/oauth/register"

# Registration request payload
registration_payload = {
  redirect_uris: ["http://localhost:3000/callback"],
  client_name: "Protected Registration Client",
  grant_types: ["authorization_code"],
  response_types: ["code"]
}

valid_token = "my-secret-initial-access-token-12345"
invalid_token = "invalid-token"

puts "=" * 70
puts "RFC 7591 Dynamic Client Registration - Protected Registration"
puts "=" * 70
puts
puts "When dcr_require_initial_access_token is enabled, clients must"
puts "present a valid initial access token in the Authorization header."
puts
puts "Registration endpoint: #{register_url}"
puts
puts "Request payload:"
puts JSON.pretty_generate(registration_payload)
puts

# First, demonstrate failure without token
puts "=" * 70
puts "TEST 1: Registration WITHOUT initial access token"
puts "=" * 70
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
puts "Sending registration request (no token)..."
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
puts
puts "Result: #{(response.code == "401") ? "EXPECTED - Rejected without token" : "UNEXPECTED"}"
puts

# Next, demonstrate failure with invalid token
puts "=" * 70
puts "TEST 2: Registration WITH INVALID initial access token"
puts "=" * 70
puts
puts "-" * 70
puts "Equivalent curl command:"
puts "-" * 70
puts <<~CURL
  curl -X POST #{register_url} \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer #{invalid_token}" \\
    -d '#{registration_payload.to_json}'
CURL
puts
puts "-" * 70
puts "Sending registration request (invalid token)..."
puts "-" * 70

request = Net::HTTP::Post.new(uri.path)
request["Content-Type"] = "application/json"
request["Authorization"] = "Bearer #{invalid_token}"
request.body = registration_payload.to_json

response = http.request(request)
body = JSON.parse(response.body)

puts
puts "Response status: #{response.code}"
puts "Response body:"
puts JSON.pretty_generate(body)
puts
puts "Result: #{(response.code == "401") ? "EXPECTED - Rejected with invalid token" : "UNEXPECTED"}"
puts

# Finally, demonstrate success with valid token
puts "=" * 70
puts "TEST 3: Registration WITH VALID initial access token"
puts "=" * 70
puts
puts "-" * 70
puts "Equivalent curl command:"
puts "-" * 70
puts <<~CURL
  curl -X POST #{register_url} \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer #{valid_token}" \\
    -d '#{registration_payload.to_json}'
CURL
puts
puts "-" * 70
puts "Sending registration request (valid token)..."
puts "-" * 70

request = Net::HTTP::Post.new(uri.path)
request["Content-Type"] = "application/json"
request["Authorization"] = "Bearer #{valid_token}"
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
  puts "SUCCESS! Client registered with valid initial access token."
  puts "=" * 70
  puts
  puts "Client ID:     #{client_id}"
  puts "Client Secret: #{client_secret}"
end

# Reset configuration
TokenAuthority.config.dcr_require_initial_access_token = false
TokenAuthority.config.dcr_initial_access_token_validator = nil
puts
puts "(Configuration reset to disable protected registration)"
