# frozen_string_literal: true

# URL-Based Client Authorization Flow (Client Metadata Documents)
#
# This script demonstrates the OAuth flow using a URL-based client_id,
# where client metadata is fetched from the URL at runtime.
#
# Features demonstrated:
#   - Discovery via well-known metadata endpoints
#   - Client Metadata Documents (draft-ietf-oauth-client-id-metadata-document)
#   - OAuth Scopes for permission control
#   - Resource Indicators (RFC 8707) for audience binding
#   - PKCE with S256 (required for public clients)
#
# Prerequisites:
#   1. Start the metadata server: ruby script/serve_client_metadata.rb
#   2. Expose it via ngrok: ngrok http 4567
#   3. Start the Rails server: bin/rails server
#
# Usage:
#   rails runner script/client_metadata_document.rb
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
REDIRECT_URI = "http://localhost:3000/callback"

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

def http_get(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  request = Net::HTTP::Get.new(uri.request_uri)
  request["Accept"] = "application/json"
  http.request(request)
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

def fetch_authorization_server_metadata(base_url)
  url = "#{base_url}/.well-known/oauth-authorization-server"
  response = http_get(url)

  unless response.code == "200"
    puts "ERROR: Failed to fetch authorization server metadata from #{url}"
    puts "Response: #{response.code} #{response.message}"
    exit 1
  end

  JSON.parse(response.body)
end

def fetch_protected_resource_metadata(base_url)
  url = "#{base_url}/.well-known/oauth-protected-resource"
  response = http_get(url)

  unless response.code == "200"
    puts "ERROR: Failed to fetch protected resource metadata from #{url}"
    puts "Response: #{response.code} #{response.message}"
    exit 1
  end

  JSON.parse(response.body)
end

def display_available_resources(resource_metadata)
  resource_uri = resource_metadata["resource"]
  resource_name = resource_metadata["resource_name"] || resource_uri

  puts "Protected Resource (from /.well-known/oauth-protected-resource):"
  puts "  [1] #{resource_name}"
  puts "      #{resource_uri}"

  [resource_uri]
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

def display_available_scopes(auth_server_metadata)
  scopes = auth_server_metadata["scopes_supported"]

  if scopes.nil? || scopes.empty?
    puts "OAuth Scopes: No scopes advertised by server"
    return []
  end

  puts "Scopes Supported (from /.well-known/oauth-authorization-server):"
  scopes.each_with_index do |scope, index|
    puts "  [#{index + 1}] #{scope}"
  end

  scopes
end

def select_scopes(available_scopes)
  return nil if available_scopes.empty?

  puts
  puts "Enter scopes to request:"
  puts "  - Press Enter for no scopes"
  puts "  - Enter numbers (comma-separated) to select specific scopes"
  puts "  - Or type scope names directly (space-separated)"
  print "> "
  input = gets&.chomp&.strip

  return nil if input.nil? || input.empty?

  # Check if input looks like numbers (comma-separated)
  if input.match?(/^[\d,\s]+$/)
    indices = input.split(",").map { |s| s.strip.to_i - 1 }
    selected = indices.select { |i| i >= 0 && i < available_scopes.length }
      .map { |i| available_scopes[i] }
    selected.join(" ")
  else
    # Treat as space-separated scope names
    input
  end
end

def open_in_browser(url)
  puts "Opening authorization URL in your browser..."

  case RUBY_PLATFORM
  when /darwin/
    system("open", url)
  when /linux/
    system("xdg-open", url)
  when /mswin|mingw/
    system("start", url)
  else
    puts "Could not auto-open browser. Please open this URL manually:"
    puts url
  end
end

# =============================================================================
# STEP 1: Discovery - Fetch Metadata
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

subsection "STEP 1: Discovery - Fetch Server Metadata"

puts "Fetching authorization server metadata..."
auth_server_metadata = fetch_authorization_server_metadata(BASE_URL)

puts "Fetching protected resource metadata..."
resource_metadata = fetch_protected_resource_metadata(BASE_URL)

puts
puts "Authorization Server Metadata:"
puts "  Issuer:                #{auth_server_metadata["issuer"]}"
puts "  Authorization Endpoint: #{auth_server_metadata["authorization_endpoint"]}"
puts "  Token Endpoint:         #{auth_server_metadata["token_endpoint"]}"

puts
puts "Protected Resource Metadata:"
puts "  Resource:              #{resource_metadata["resource"]}"
puts "  Resource Name:         #{resource_metadata["resource_name"]}" if resource_metadata["resource_name"]
puts "  Authorization Servers: #{resource_metadata["authorization_servers"]&.join(", ")}"

# =============================================================================
# STEP 2: Collect Client Information
# =============================================================================

section "STEP 2: Client Metadata Document URL"

puts "Enter the client_id URL where your client metadata document is hosted."
puts "This must be an HTTPS URL with a path (e.g., https://abc123.ngrok-free.app/oauth-client)"
puts

print "Enter the client_id URL: "
client_id = gets&.chomp&.strip

if client_id.nil? || client_id.empty?
  puts "No client_id provided. Exiting."
  exit 1
end

# =============================================================================
# STEP 3: Resource Indicators (RFC 8707)
# =============================================================================

section "STEP 3: Resource Indicators (RFC 8707)"

puts "RFC 8707 allows clients to specify which protected resources they want"
puts "to access. This binds the access token to specific audiences via the"
puts "JWT 'aud' claim, preventing token reuse across different services."
puts

available_resources = display_available_resources(resource_metadata)
selected_resources = select_resources(available_resources)

puts
if selected_resources.any?
  puts "Selected resources:"
  selected_resources.each { |r| puts "  - #{r}" }
else
  puts "No resources selected. Token will use default audience."
end

# =============================================================================
# STEP 4: OAuth Scopes
# =============================================================================

section "STEP 4: OAuth Scopes"

puts "Scopes define what permissions the client is requesting. Users will see"
puts "the scope descriptions on the consent screen."
puts

available_scopes = display_available_scopes(auth_server_metadata)
selected_scope = select_scopes(available_scopes)

puts
if selected_scope && !selected_scope.empty?
  puts "Selected scopes: #{selected_scope}"
else
  puts "No scopes selected."
end

# =============================================================================
# STEP 5: Generate PKCE Parameters
# =============================================================================

section "STEP 5: Generate PKCE Parameters"

puts "URL-based clients are always PUBLIC clients and REQUIRE PKCE with S256."
puts

pkce = generate_pkce

puts "Generated PKCE parameters:"
puts
puts "  Code Verifier:  #{pkce[:verifier]}"
puts "  Code Challenge: #{pkce[:challenge]}"
puts "  Method:         #{pkce[:method]}"

# =============================================================================
# STEP 6: Authorization Request
# =============================================================================

section "STEP 6: Authorization Request"

auth_params = {
  client_id: client_id,
  redirect_uri: REDIRECT_URI,
  response_type: "code",
  code_challenge: pkce[:challenge],
  code_challenge_method: pkce[:method],
  state: SecureRandom.hex(16)
}

# Add scope parameter if selected
auth_params[:scope] = selected_scope if selected_scope && !selected_scope.empty?

# Add resource parameters (RFC 8707)
# Note: Multiple resources are sent as repeated 'resource' params
auth_query_parts = URI.encode_www_form(auth_params)
if selected_resources.any?
  resource_params = selected_resources.map { |r| "resource=#{CGI.escape(r)}" }.join("&")
  auth_query_parts = "#{auth_query_parts}&#{resource_params}"
end

auth_url = "#{auth_server_metadata["authorization_endpoint"]}?#{auth_query_parts}"

puts "Parameters:"
puts "  client_id:             #{client_id}"
puts "  redirect_uri:          #{REDIRECT_URI}"
puts "  response_type:         code"
puts "  code_challenge:        #{pkce[:challenge]}"
puts "  code_challenge_method: S256"
puts "  state:                 #{auth_params[:state]}"
if selected_scope && !selected_scope.empty?
  puts "  scope:                 #{selected_scope}"
end
if selected_resources.any?
  puts "  resource:              #{selected_resources.join(", ")}"
end
puts

open_in_browser(auth_url)

# =============================================================================
# STEP 7: Token Exchange
# =============================================================================

section "STEP 7: Token Exchange"

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

token_endpoint = auth_server_metadata["token_endpoint"]

if authorization_code.nil? || authorization_code.empty?
  puts
  puts "No authorization code provided. Here's the curl command you would use:"
  puts
  curl_cmd = <<~CURL
    curl -X POST #{token_endpoint} \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "client_id=#{CGI.escape(client_id)}" \\
      -d "redirect_uri=#{CGI.escape(REDIRECT_URI)}" \\
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
  redirect_uri: REDIRECT_URI,
  code_verifier: pkce[:verifier]
}

puts "Token endpoint: #{token_endpoint}"
puts
puts "Request parameters:"
token_params.each { |k, v| puts "  #{k}: #{v}" }
token_resources.each { |r| puts "  resource: #{r}" }

response = http_post(token_endpoint, form_data: token_params, resources: token_resources)
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
puts "  Scope:         #{token_response["scope"]}" if token_response["scope"]

# Decode and display JWT claims
jwt_payload = decode_jwt_payload(access_token)
if jwt_payload
  subsection "JWT Access Token Claims"

  puts "Key claims from the access token:"
  puts
  puts "  iss (issuer):   #{jwt_payload["iss"]}"
  puts "  sub (subject):  #{jwt_payload["sub"]}"
  puts "  aud (audience): #{jwt_payload["aud"].is_a?(Array) ? jwt_payload["aud"].join(", ") : jwt_payload["aud"]}"
  puts "  scope:          #{jwt_payload["scope"] || "(none)"}"
  puts "  exp (expires):  #{Time.at(jwt_payload["exp"]).utc}" if jwt_payload["exp"]
  puts "  jti (token id): #{jwt_payload["jti"]}"

  if jwt_payload["scope"]
    puts
    puts "The 'scope' claim contains the permissions granted to this token."
    puts "Resource servers should validate required scopes before allowing access."
  end

  if token_resources.any?
    puts
    puts "The 'aud' claim contains the resource(s) you requested."
    puts "Resource servers should validate that their URI is in the 'aud' claim"
    puts "before accepting this token."
  end
end

# =============================================================================
# STEP 8: Using the Access Token
# =============================================================================

section "STEP 8: Using the Access Token"

puts "Example API request with the access token:"
puts
resource_url = token_resources.first || resource_metadata["resource"]
puts <<~CURL
  curl -X GET #{resource_url}v1/users/current \\
    -H "Authorization: Bearer #{access_token}"
CURL

puts
puts "MCP spec requirements for token usage:"
puts "  - Tokens MUST be sent in Authorization header (not query string)"
puts "  - Tokens MUST be included in EVERY request"
puts "  - Invalid/expired tokens receive HTTP 401"
puts "  - Insufficient scope receives HTTP 403"

# =============================================================================
# STEP 9: Refreshing Tokens
# =============================================================================

if refresh_token
  section "STEP 9: Refreshing Tokens"

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
    curl -X POST #{token_endpoint} \\
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
puts "  1. Discovery"
puts "     - Fetched authorization server metadata from /.well-known/oauth-authorization-server"
puts "     - Fetched protected resource metadata from /.well-known/oauth-protected-resource"
puts
puts "  2. Client metadata fetched from: #{client_id}"
puts
puts "  3. Resource Indicators (RFC 8707) for audience binding"
if token_resources.any?
  token_resources.each { |r| puts "     - #{r}" }
end
puts
puts "  4. OAuth Scopes for permission control"
if selected_scope && !selected_scope.empty?
  puts "     - #{selected_scope}"
end
puts
puts "  5. PKCE with S256 (required for public clients)"
puts
puts "  6. Token exchange without client secret"
puts
puts "Key differences from registered clients:"
puts "  - client_id is an HTTPS URL, not a UUID"
puts "  - Metadata is fetched at runtime (cached by server)"
puts "  - Always treated as a public client"
puts "  - PKCE is mandatory"
puts
puts "For more information, see:"
puts "  - Client Metadata: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document"
puts "  - OAuth Scopes: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3"
puts "  - Resource Indicators: https://www.rfc-editor.org/rfc/rfc8707.html"
