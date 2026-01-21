# frozen_string_literal: true

# Script to register a client using client_secret_post authentication.
# With this method, the client sends credentials in the request body instead of
# the Authorization header.
#
# Usage:
#   rails runner script/register_client_secret_post.rb

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
  redirect_uris: ["http://localhost:3000/callback"],
  client_name: "Client Secret Post App",
  token_endpoint_auth_method: "client_secret_post",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"]
}

puts "=" * 70
puts "RFC 7591 Dynamic Client Registration - client_secret_post"
puts "=" * 70
puts
puts "With client_secret_post, the client authenticates by including"
puts "client_id and client_secret in the request body (form data)."
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
  puts "Token exchange with client_secret_post"
  puts "-" * 70
  puts
  puts "With client_secret_post, credentials go in the request body:"
  puts

  code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")
  code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")
  redirect_uri = body["redirect_uris"].first

  puts "1. Authorize URL:"
  puts
  puts "   #{base_url}/oauth/authorize?client_id=#{client_id}&redirect_uri=#{redirect_uri}&response_type=code&code_challenge=#{code_challenge}&code_challenge_method=S256"
  puts
  puts "2. Token exchange (note: credentials in body, not Authorization header):"
  puts
  puts <<~CURL
    curl -X POST #{base_url}/oauth/token \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "client_id=#{client_id}" \\
      -d "client_secret=#{client_secret}" \\
      -d "redirect_uri=#{redirect_uri}" \\
      -d "code_verifier=#{code_verifier}"
  CURL
  puts
  puts "   Code Verifier: #{code_verifier}"
else
  puts
  puts "=" * 70
  puts "FAILED! Registration error."
  puts "=" * 70
  puts
  puts "Error: #{body["error"]}"
  puts "Description: #{body["error_description"]}"
end
