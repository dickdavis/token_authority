# frozen_string_literal: true

# URL-Based Client Authorization Flow (Client Metadata Documents)
#
# This script demonstrates the OAuth flow using a URL-based client_id,
# where client metadata is fetched from the URL at runtime.
#
# Features demonstrated:
#   - Client Metadata Documents (draft-ietf-oauth-client-id-metadata-document)
#   - Resource Indicators (RFC 8707) for audience binding
#   - PKCE with S256 (required for public clients)
#
# Prerequisites:
#   1. Start the metadata server: ruby script/serve_client_metadata.rb
#   2. Expose it via ngrok: ngrok http 4567
#   3. Start the Rails server: bin/rails server
#
# Usage:
#   rails runner script/mcp_client_metadata_document.rb
#
# References:
#   - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document
#   - https://www.rfc-editor.org/rfc/rfc8707.html

require "base64"
require "cgi"
require "digest"
require "json"
require "net/http"
require "uri"

# =============================================================================
# Configuration
# =============================================================================

BASE_URL = "http://localhost:3000"
DEFAULT_REDIRECT_URI = "http://localhost:3000/callback"

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

def http_post(url, form_data:, resources: [])
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)

  request = Net::HTTP::Post.new(uri.path)

  # Build form body manually to support multiple resource params
  body_parts = form_data.map { |k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }
  resources.each { |r| body_parts << "resource=#{CGI.escape(r)}" }

  request["Content-Type"] = "application/x-www-form-urlencoded"
  request.body = body_parts.join("&")

  http.request(request)
end

def generate_pkce
  # Generate code_verifier: 43-128 characters, URL-safe
  code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")

  # Generate code_challenge: SHA256 hash of verifier, base64url encoded
  code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")

  {verifier: code_verifier, challenge: code_challenge, method: "S256"}
end

def decode_jwt_payload(token)
  # Decode JWT payload (middle part) without verification
  parts = token.split(".")
  return nil unless parts.length == 3

  payload = parts[1]
  # Add padding if needed
  payload += "=" * (4 - payload.length % 4) if payload.length % 4 != 0
  JSON.parse(Base64.urlsafe_decode64(payload))
rescue
  nil
end

def display_configured_resources
  resources = TokenAuthority.config.rfc_8707_resources

  if resources.nil? || resources.empty?
    puts "RFC 8707 Resource Indicators: DISABLED"
    puts "  No resources configured. Tokens will use default audience."
    return []
  end

  puts "RFC 8707 Resource Indicators: ENABLED"
  puts
  puts "Configured resources (allowlist):"
  resources.each_with_index do |(uri, display_name), index|
    puts "  [#{index + 1}] #{display_name}"
    puts "      #{uri}"
  end

  resources.keys
end

def select_resources(available_resources)
  return [] if available_resources.empty?

  puts
  puts "Enter resource numbers to request (comma-separated), or press Enter for all:"
  print "> "
  input = gets&.chomp&.strip

  if input.nil? || input.empty?
    available_resources
  else
    indices = input.split(",").map { |s| s.strip.to_i - 1 }
    indices.select { |i| i >= 0 && i < available_resources.length }
      .map { |i| available_resources[i] }
  end
end

# =============================================================================
# STEP 1: Collect Client Information
# =============================================================================

section "URL-Based Client Authorization Flow"

puts "URL-based clients use an HTTPS URL as their client_id. The authorization"
puts "server fetches client metadata from this URL at runtime."
puts
puts "Before continuing, ensure you have:"
puts "  1. Started the metadata server: ruby script/serve_client_metadata.rb"
puts "  2. Exposed it via ngrok: ngrok http 4567"
puts "  3. Started the Rails server: bin/rails server"
puts

print "Enter the client_id URL (e.g., https://abc123.ngrok-free.app/oauth-client): "
client_id = gets&.chomp&.strip

if client_id.nil? || client_id.empty?
  puts "No client_id provided. Exiting."
  exit 1
end

print "Enter the redirect_uri [#{DEFAULT_REDIRECT_URI}]: "
input_redirect_uri = gets&.chomp&.strip
redirect_uri = input_redirect_uri.empty? ? DEFAULT_REDIRECT_URI : input_redirect_uri

# =============================================================================
# STEP 2: Resource Indicators (RFC 8707)
# =============================================================================

section "STEP 1: Resource Indicators (RFC 8707)"

puts "RFC 8707 allows clients to specify which protected resources they want"
puts "to access. This binds the access token to specific audiences via the"
puts "JWT 'aud' claim, preventing token reuse across different services."
puts

available_resources = display_configured_resources
selected_resources = select_resources(available_resources)

puts
if selected_resources.any?
  puts "Selected resources:"
  selected_resources.each { |r| puts "  - #{r}" }
else
  puts "No resources selected. Token will use default audience from config."
end

# =============================================================================
# STEP 3: Generate PKCE Parameters
# =============================================================================

section "STEP 2: Generate PKCE Parameters"

puts "URL-based clients are always PUBLIC clients and REQUIRE PKCE with S256."
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

auth_params = {
  client_id: client_id,
  redirect_uri: redirect_uri,
  response_type: "code",
  code_challenge: pkce[:challenge],
  code_challenge_method: pkce[:method],
  state: SecureRandom.hex(16)
}

# Add resource parameters (RFC 8707)
# Note: Multiple resources are sent as repeated 'resource' params
auth_query_parts = URI.encode_www_form(auth_params)
if selected_resources.any?
  resource_params = selected_resources.map { |r| "resource=#{CGI.escape(r)}" }.join("&")
  auth_query_parts = "#{auth_query_parts}&#{resource_params}"
end

auth_url = "#{BASE_URL}/oauth/authorize?#{auth_query_parts}"

puts "Parameters:"
puts "  client_id:             #{client_id}"
puts "  redirect_uri:          #{redirect_uri}"
puts "  response_type:         code"
puts "  code_challenge:        #{pkce[:challenge]}"
puts "  code_challenge_method: S256"
puts "  state:                 #{auth_params[:state]}"
if selected_resources.any?
  puts "  resource:              #{selected_resources.join(", ")}"
end
puts
puts "Opening authorization URL in your browser..."

# Open URL in default browser
case RUBY_PLATFORM
when /darwin/
  system("open", auth_url)
when /linux/
  system("xdg-open", auth_url)
when /mswin|mingw/
  system("start", auth_url)
else
  puts "Could not auto-open browser. Please open this URL manually:"
  puts auth_url
end

# =============================================================================
# STEP 4: Token Exchange
# =============================================================================

section "STEP 4: Token Exchange"

puts "After user authorizes, you'll be redirected with an authorization code."
puts
puts "For URL-based (PUBLIC) clients:"
puts "  - No client authentication (no Authorization header)"
puts "  - Client ID sent in request body"
puts "  - PKCE code_verifier proves client identity"
puts
if selected_resources.any?
  puts "RFC 8707 Downscoping:"
  puts "  At token exchange, you can request a SUBSET of the resources"
  puts "  that were granted during authorization. This is useful for"
  puts "  obtaining tokens with minimal necessary permissions."
  puts
end

print "Enter the authorization code from the redirect: "
authorization_code = gets&.chomp

if authorization_code.nil? || authorization_code.empty?
  puts
  puts "No authorization code provided. Here's the curl command you would use:"
  puts
  curl_cmd = <<~CURL
    curl -X POST #{BASE_URL}/oauth/token \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "client_id=#{CGI.escape(client_id)}" \\
      -d "redirect_uri=#{CGI.escape(redirect_uri)}" \\
      -d "code_verifier=#{pkce[:verifier]}"
  CURL
  if selected_resources.any?
    resource_flags = selected_resources.map { |r| "-d \"resource=#{CGI.escape(r)}\"" }.join(" \\\n      ")
    curl_cmd = curl_cmd.chomp + " \\\n      #{resource_flags}\n"
  end
  puts curl_cmd
  exit 0
end

# Optionally downscope resources at token exchange
token_resources = selected_resources
if selected_resources.length > 1
  puts
  puts "You authorized #{selected_resources.length} resources. You can downscope now."
  puts "Enter resource numbers to include in token (comma-separated), or Enter for all:"
  selected_resources.each_with_index { |r, i| puts "  [#{i + 1}] #{r}" }
  print "> "
  downscope_input = gets&.chomp&.strip

  unless downscope_input.nil? || downscope_input.empty?
    indices = downscope_input.split(",").map { |s| s.strip.to_i - 1 }
    token_resources = indices.select { |i| i >= 0 && i < selected_resources.length }
      .map { |i| selected_resources[i] }
    if token_resources.any? && token_resources != selected_resources
      puts
      puts "Downscoped to: #{token_resources.join(", ")}"
    end
  end
end

subsection "Exchanging authorization code for tokens..."

token_params = {
  grant_type: "authorization_code",
  code: authorization_code,
  client_id: client_id,
  redirect_uri: redirect_uri,
  code_verifier: pkce[:verifier]
}

puts "Token endpoint: #{BASE_URL}/oauth/token"
puts
puts "Request parameters:"
token_params.each { |k, v| puts "  #{k}: #{v}" }
token_resources.each { |r| puts "  resource: #{r}" }

response = http_post("#{BASE_URL}/oauth/token", form_data: token_params, resources: token_resources)
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

# Decode and display JWT claims
jwt_payload = decode_jwt_payload(access_token)
if jwt_payload
  subsection "JWT Access Token Claims (RFC 8707 Audience Binding)"

  puts "Key claims from the access token:"
  puts
  puts "  iss (issuer):   #{jwt_payload["iss"]}"
  puts "  sub (subject):  #{jwt_payload["sub"]}"
  puts "  aud (audience): #{jwt_payload["aud"].is_a?(Array) ? jwt_payload["aud"].join(", ") : jwt_payload["aud"]}"
  puts "  exp (expires):  #{Time.at(jwt_payload["exp"]).utc}" if jwt_payload["exp"]
  puts "  jti (token id): #{jwt_payload["jti"]}"

  if token_resources.any?
    puts
    puts "The 'aud' claim contains the resource(s) you requested."
    puts "Resource servers should validate that their URI is in the 'aud' claim"
    puts "before accepting this token."
  end
end

# =============================================================================
# STEP 5: Using the Access Token
# =============================================================================

section "STEP 5: Using the Access Token"

puts "Example API request with the access token:"
puts
puts <<~CURL
  curl -X GET #{BASE_URL}/api/some-endpoint \\
    -H "Authorization: Bearer #{access_token}"
CURL

if token_resources.any?
  puts
  puts "The resource server at #{token_resources.first} should:"
  puts "  1. Decode and verify the JWT signature"
  puts "  2. Check that its resource URI is in the 'aud' claim"
  puts "  3. Reject tokens not audience-bound to it"
end

# =============================================================================
# STEP 6: Refreshing Tokens
# =============================================================================

if refresh_token
  section "STEP 6: Refreshing Tokens"

  puts "For public clients, refresh tokens are rotated on each use."
  puts
  if token_resources.any?
    puts "RFC 8707 Note: When refreshing, you can request a subset of the"
    puts "originally granted resources (further downscoping)."
    puts
  end
  puts "Refresh token request:"
  puts
  refresh_curl = <<~CURL
    curl -X POST #{BASE_URL}/oauth/token \\
      -d "grant_type=refresh_token" \\
      -d "refresh_token=#{refresh_token}" \\
      -d "client_id=#{CGI.escape(client_id)}"
  CURL
  if token_resources.any?
    resource_flags = token_resources.map { |r| "-d \"resource=#{CGI.escape(r)}\"" }.join(" \\\n      ")
    refresh_curl = refresh_curl.chomp + " \\\n      #{resource_flags}\n"
  end
  puts refresh_curl
end

# =============================================================================
# Summary
# =============================================================================

section "URL-Based Client Authorization Complete"

puts "This script demonstrated the OAuth flow with a URL-based client_id:"
puts
puts "  1. Client metadata fetched from: #{client_id}"
puts "  2. Resource Indicators (RFC 8707) for audience binding"
puts "  3. PKCE with S256 (required for public clients)"
puts "  4. Token exchange without client secret"
puts
if token_resources.any?
  puts "RFC 8707 Resource Indicators used:"
  token_resources.each { |r| puts "  - #{r}" }
  puts
  puts "The access token's 'aud' claim is bound to these resources."
  puts "Resource servers should verify their URI is in the audience."
  puts
end
puts "Key differences from registered clients:"
puts "  - client_id is an HTTPS URL, not a UUID"
puts "  - Metadata is fetched at runtime (cached by server)"
puts "  - Always treated as a public client"
puts "  - PKCE is mandatory"
puts
puts "For more information, see:"
puts "  - Client Metadata: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document"
puts "  - Resource Indicators: https://www.rfc-editor.org/rfc/rfc8707.html"
