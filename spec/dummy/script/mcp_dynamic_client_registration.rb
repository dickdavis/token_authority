# frozen_string_literal: true

# MCP Dynamic Client Registration & OAuth Flow
#
# This script demonstrates the critical path for MCP authorization:
# 1. Dynamic Client Registration (RFC 7591) - Register a public client
# 2. OAuth 2.1 Authorization Code Flow with PKCE (S256)
# 3. Resource parameter for audience binding (RFC 8707)
#
# Per the MCP spec, public clients (token_endpoint_auth_method: "none") with
# PKCE are the preferred approach for dynamic registration scenarios.
#
# Usage:
#   rails runner script/mcp_dynamic_client_registration.rb
#
# Reference: https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization

require "net/http"
require "json"
require "uri"
require "digest"

# =============================================================================
# Configuration
# =============================================================================

BASE_URL = "http://localhost:3000"
RESOURCE_URL = "#{BASE_URL}/api/" # The protected resource (audience)
REDIRECT_URI = "http://127.0.0.1:3000/callback" # MCP spec prefers 127.0.0.1 for localhost

# Verify dynamic registration is enabled
unless TokenAuthority.config.rfc_7591_enabled
  puts "ERROR: Dynamic client registration is not enabled."
  puts "Add this to your TokenAuthority initializer:"
  puts "  config.rfc_7591_enabled = true"
  exit 1
end

# =============================================================================
# Helper Methods
# =============================================================================

def section(title)
  puts
  puts "=" * 70
  puts title
  puts "=" * 70
  puts
end

def subsection(title)
  puts
  puts "-" * 70
  puts title
  puts "-" * 70
  puts
end

def http_post(url, body: nil, headers: {}, form_data: nil)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)

  request = Net::HTTP::Post.new(uri.path)
  headers.each { |k, v| request[k] = v }

  if body
    request["Content-Type"] = "application/json"
    request.body = body.to_json
  elsif form_data
    request.set_form_data(form_data)
  end

  http.request(request)
end

def generate_pkce
  # Generate code_verifier: 43-128 characters, URL-safe
  code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")

  # Generate code_challenge: SHA256 hash of verifier, base64url encoded
  code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")

  {verifier: code_verifier, challenge: code_challenge, method: "S256"}
end

# =============================================================================
# STEP 1: Dynamic Client Registration (RFC 7591)
# =============================================================================

section "STEP 1: Dynamic Client Registration (RFC 7591)"

puts "MCP spec prefers PUBLIC clients for dynamic registration scenarios."
puts "Public clients use token_endpoint_auth_method: 'none' and rely on PKCE."
puts

registration_payload = {
  # Required
  redirect_uris: [REDIRECT_URI],

  # Client metadata
  client_name: "MCP Test Client",
  client_uri: "https://example.com/mcp-client",

  # MCP-preferred: Public client (no client secret)
  token_endpoint_auth_method: "none",

  # Standard OAuth grants for authorization code flow
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],

  # Optional: Contact for the client developer
  contacts: ["developer@example.com"]
}

register_url = "#{BASE_URL}/oauth/register"

puts "Registration endpoint: #{register_url}"
puts
puts "Request payload:"
puts JSON.pretty_generate(registration_payload)

subsection "Equivalent curl command"
puts <<~CURL
  curl -X POST #{register_url} \\
    -H "Content-Type: application/json" \\
    -d '#{registration_payload.to_json}'
CURL

subsection "Sending registration request..."

response = http_post(register_url, body: registration_payload)
registration_response = JSON.parse(response.body)

puts "Response status: #{response.code}"
puts "Response body:"
puts JSON.pretty_generate(registration_response)

unless response.code == "201"
  puts
  puts "ERROR: Registration failed!"
  puts "Error: #{registration_response["error"]}"
  puts "Description: #{registration_response["error_description"]}"
  exit 1
end

client_id = registration_response["client_id"]

puts
puts "SUCCESS! Public client registered."
puts
puts "  Client ID:   #{client_id}"
puts "  Auth Method: #{registration_response["token_endpoint_auth_method"]}"
puts "  Note: No client_secret (public client)"

# =============================================================================
# STEP 2: Generate PKCE Parameters
# =============================================================================

section "STEP 2: Generate PKCE Parameters"

puts "MCP spec REQUIRES PKCE with S256 for all authorization flows."
puts

pkce = generate_pkce

puts "Generated PKCE parameters:"
puts
puts "  Code Verifier:  #{pkce[:verifier]}"
puts "  Code Challenge: #{pkce[:challenge]}"
puts "  Method:         #{pkce[:method]}"

# =============================================================================
# STEP 3: Build Authorization URL
# =============================================================================

section "STEP 3: Authorization Request"

puts "MCP spec REQUIRES the 'resource' parameter (RFC 8707) to bind tokens"
puts "to their intended audience, preventing token reuse across services."
puts

auth_params = {
  client_id: client_id,
  redirect_uri: REDIRECT_URI,
  response_type: "code",
  code_challenge: pkce[:challenge],
  code_challenge_method: pkce[:method],
  resource: RESOURCE_URL # RFC 8707: Audience binding
  # scope: "read write"  # Optional: Add scopes if needed
}

auth_url = "#{BASE_URL}/oauth/authorize?#{URI.encode_www_form(auth_params)}"

puts "Authorization URL (open in browser):"
puts
puts auth_url
puts
puts "Parameters breakdown:"
puts "  client_id:             #{client_id}"
puts "  redirect_uri:          #{REDIRECT_URI}"
puts "  response_type:         code"
puts "  code_challenge:        #{pkce[:challenge]}"
puts "  code_challenge_method: S256"
puts "  resource:              #{RESOURCE_URL} (audience binding)"

# =============================================================================
# STEP 4: Token Exchange
# =============================================================================

section "STEP 4: Token Exchange"

puts "After user authorizes, exchange the code for tokens."
puts
puts "For PUBLIC clients:"
puts "  - No client authentication (no Authorization header)"
puts "  - Client ID sent in request body"
puts "  - PKCE code_verifier proves client identity"
puts

print "Enter the authorization code from the redirect: "
authorization_code = gets&.chomp

if authorization_code.nil? || authorization_code.empty?
  puts
  puts "No authorization code provided. Here's the curl command you would use:"
  puts
  puts <<~CURL
    curl -X POST #{BASE_URL}/oauth/token \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "client_id=#{client_id}" \\
      -d "redirect_uri=#{REDIRECT_URI}" \\
      -d "code_verifier=#{pkce[:verifier]}" \\
      -d "resource=#{RESOURCE_URL}"
  CURL
  exit 0
end

subsection "Exchanging authorization code for tokens..."

token_params = {
  grant_type: "authorization_code",
  code: authorization_code,
  client_id: client_id,
  redirect_uri: REDIRECT_URI,
  code_verifier: pkce[:verifier],
  resource: RESOURCE_URL
}

puts "Token endpoint: #{BASE_URL}/oauth/token"
puts
puts "Request parameters:"
token_params.each { |k, v| puts "  #{k}: #{v}" }

response = http_post("#{BASE_URL}/oauth/token", form_data: token_params)
token_response = JSON.parse(response.body)

puts
puts "Response status: #{response.code}"
puts "Response body:"
puts JSON.pretty_generate(token_response)

unless response.code == "200"
  puts
  puts "ERROR: Token exchange failed!"
  puts "Error: #{token_response["error"]}"
  puts "Description: #{token_response["error_description"]}"
  exit 1
end

access_token = token_response["access_token"]
refresh_token = token_response["refresh_token"]

puts
puts "SUCCESS! Tokens received."
puts
puts "  Access Token:  #{access_token[0..50]}..."
puts "  Refresh Token: #{refresh_token[0..50]}..." if refresh_token
puts "  Token Type:    #{token_response["token_type"]}"
puts "  Expires In:    #{token_response["expires_in"]} seconds"

# =============================================================================
# STEP 5: Using the Access Token
# =============================================================================

section "STEP 5: Using the Access Token"

puts "MCP spec requirements for token usage:"
puts
puts "  - Tokens MUST be sent in Authorization header (not query string)"
puts "  - Tokens MUST be included in EVERY request"
puts "  - Invalid/expired tokens receive HTTP 401"
puts "  - Insufficient scope receives HTTP 403"
puts

puts "Example API request:"
puts
puts <<~CURL
  curl -X GET #{RESOURCE_URL}some-endpoint \\
    -H "Authorization: Bearer #{access_token}"
CURL

# =============================================================================
# STEP 6: Refreshing Tokens (Optional)
# =============================================================================

if refresh_token
  section "STEP 6: Refreshing Tokens"

  puts "MCP spec notes on refresh tokens:"
  puts
  puts "  - For public clients, refresh tokens MUST be rotated"
  puts "  - Short-lived access tokens are recommended"
  puts

  puts "Refresh token request:"
  puts
  puts <<~CURL
    curl -X POST #{BASE_URL}/oauth/token \\
      -d "grant_type=refresh_token" \\
      -d "refresh_token=#{refresh_token}" \\
      -d "client_id=#{client_id}" \\
      -d "resource=#{RESOURCE_URL}"
  CURL
end

# =============================================================================
# Summary
# =============================================================================

section "MCP Authorization Flow Complete"

puts "This script demonstrated the MCP-preferred authorization flow:"
puts
puts "  1. Dynamic Client Registration (RFC 7591)"
puts "     - Public client (token_endpoint_auth_method: none)"
puts "     - No client secret issued"
puts
puts "  2. Authorization Code Flow with PKCE"
puts "     - S256 code challenge method (mandatory)"
puts "     - Resource parameter for audience binding (mandatory)"
puts
puts "  3. Token Exchange"
puts "     - Public client authentication via PKCE"
puts "     - No client_secret required"
puts
puts "  4. Token Usage"
puts "     - Bearer token in Authorization header"
puts "     - Audience-bound to specific resource"
puts
puts "Client ID: #{client_id}"
puts
puts "For more information, see:"
puts "  https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization"
