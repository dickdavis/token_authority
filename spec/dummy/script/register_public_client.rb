# frozen_string_literal: true

# Script to register a public client using RFC 7591 Dynamic Client Registration.
# Public clients use token_endpoint_auth_method: "none" and don't receive a client_secret.
#
# Usage:
#   rails runner script/register_public_client.rb

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

# Registration request payload for public client
registration_payload = {
  redirect_uris: ["http://localhost:3000/callback"],
  client_name: "My Public App (SPA/Mobile)",
  token_endpoint_auth_method: "none", # This makes it a public client
  grant_types: ["authorization_code"],
  response_types: ["code"]
}

puts "=" * 70
puts "RFC 7591 Dynamic Client Registration - Public Client"
puts "=" * 70
puts
puts "Public clients are used for SPAs, mobile apps, or other clients that"
puts "cannot securely store a client secret. They use PKCE for security."
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

  puts
  puts "=" * 70
  puts "SUCCESS! Public client registered."
  puts "=" * 70
  puts
  puts "Client ID:   #{client_id}"
  puts "Auth Method: #{body["token_endpoint_auth_method"]}"
  puts
  puts "Note: No client_secret was issued (public clients don't have secrets)"
  puts
  puts "-" * 70
  puts "Next steps: Use this client with PKCE"
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
  puts "3. After authorization, exchange the code for tokens (no client auth needed):"
  puts
  puts <<~CURL
    curl -X POST #{base_url}/oauth/token \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "client_id=#{client_id}" \\
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
