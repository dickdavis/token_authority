# frozen_string_literal: true

# Script to register a confidential client using RFC 7591 Dynamic Client Registration.
# This demonstrates the default registration flow with client_secret_basic authentication.
#
# Usage:
#   rails runner script/register_confidential_client.rb

require "net/http"
require "json"
require "uri"

# Ensure dynamic registration is enabled
unless TokenAuthority.config.rfc_7591_enabled
  TokenAuthority.config.rfc_7591_enabled = true
  puts "Enabled dynamic client registration for this session.\n\n"
end

base_url = "http://localhost:3000"
register_url = "#{base_url}/oauth/register"

# Registration request payload
registration_payload = {
  redirect_uris: ["http://localhost:3000/callback", "http://localhost:3000/oauth/callback"],
  client_name: "My Test Application",
  client_uri: "https://example.com",
  logo_uri: "https://example.com/logo.png",
  tos_uri: "https://example.com/tos",
  policy_uri: "https://example.com/privacy",
  contacts: ["admin@example.com"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"]
  # token_endpoint_auth_method defaults to "client_secret_basic"
}

puts "=" * 70
puts "RFC 7591 Dynamic Client Registration - Confidential Client"
puts "=" * 70
puts
puts "Registration endpoint: #{register_url}"
puts
puts "Request payload:"
puts JSON.pretty_generate(registration_payload)
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
  puts "SUCCESS! Client registered."
  puts "=" * 70
  puts
  puts "Client ID:     #{client_id}"
  puts "Client Secret: #{client_secret}"
  puts "Auth Method:   #{body["token_endpoint_auth_method"]}"
  puts
  puts "-" * 70
  puts "Next steps: Use this client to start an OAuth flow"
  puts "-" * 70
  puts
  puts "1. Generate PKCE code verifier and challenge:"
  puts

  code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")
  code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")
  redirect_uri = body["redirect_uris"].first

  puts "   Code Verifier:  #{code_verifier}"
  puts "   Code Challenge: #{code_challenge}"
  puts
  puts "2. Open this URL in your browser to authorize:"
  puts
  puts "   #{base_url}/oauth/authorize?client_id=#{client_id}&redirect_uri=#{redirect_uri}&response_type=code&code_challenge=#{code_challenge}&code_challenge_method=S256"
  puts
  puts "3. After authorization, exchange the code for tokens:"
  puts
  puts <<~CURL
    curl -X POST #{base_url}/oauth/token \\
      -u "#{client_id}:#{client_secret}" \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "redirect_uri=#{redirect_uri}" \\
      -d "code_verifier=#{code_verifier}"
  CURL
else
  puts
  puts "=" * 70
  puts "FAILED! Registration error."
  puts "=" * 70
  puts
  puts "Error: #{body["error"]}"
  puts "Description: #{body["error_description"]}"
end
