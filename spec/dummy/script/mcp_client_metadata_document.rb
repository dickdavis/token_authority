# frozen_string_literal: true

# URL-Based Client Authorization Flow (Client Metadata Documents)
#
# This script demonstrates the OAuth flow using a URL-based client_id,
# where client metadata is fetched from the URL at runtime.
#
# Prerequisites:
#   1. Start the metadata server: ruby script/serve_client_metadata.rb
#   2. Expose it via ngrok: ngrok http 4567
#   3. Start the Rails server: bin/rails server
#
# Usage:
#   rails runner script/mcp_client_metadata_document.rb
#
# Reference: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document

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

def http_post(url, form_data:)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)

  request = Net::HTTP::Post.new(uri.path)
  request.set_form_data(form_data)

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
# STEP 2: Generate PKCE Parameters
# =============================================================================

section "STEP 1: Generate PKCE Parameters"

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

section "STEP 2: Authorization Request"

auth_params = {
  client_id: client_id,
  redirect_uri: redirect_uri,
  response_type: "code",
  code_challenge: pkce[:challenge],
  code_challenge_method: pkce[:method],
  state: SecureRandom.hex(16)
}

auth_url = "#{BASE_URL}/oauth/authorize?#{URI.encode_www_form(auth_params)}"

puts "Parameters:"
puts "  client_id:             #{client_id}"
puts "  redirect_uri:          #{redirect_uri}"
puts "  response_type:         code"
puts "  code_challenge:        #{pkce[:challenge]}"
puts "  code_challenge_method: S256"
puts "  state:                 #{auth_params[:state]}"
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

section "STEP 3: Token Exchange"

puts "After user authorizes, you'll be redirected with an authorization code."
puts
puts "For URL-based (PUBLIC) clients:"
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
      -d "client_id=#{CGI.escape(client_id)}" \\
      -d "redirect_uri=#{CGI.escape(redirect_uri)}" \\
      -d "code_verifier=#{pkce[:verifier]}"
  CURL
  exit 0
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

section "STEP 4: Using the Access Token"

puts "Example API request with the access token:"
puts
puts <<~CURL
  curl -X GET #{BASE_URL}/api/some-endpoint \\
    -H "Authorization: Bearer #{access_token}"
CURL

# =============================================================================
# STEP 6: Refreshing Tokens
# =============================================================================

if refresh_token
  section "STEP 5: Refreshing Tokens"

  puts "For public clients, refresh tokens are rotated on each use."
  puts
  puts "Refresh token request:"
  puts
  puts <<~CURL
    curl -X POST #{BASE_URL}/oauth/token \\
      -d "grant_type=refresh_token" \\
      -d "refresh_token=#{refresh_token}" \\
      -d "client_id=#{CGI.escape(client_id)}"
  CURL
end

# =============================================================================
# Summary
# =============================================================================

section "URL-Based Client Authorization Complete"

puts "This script demonstrated the OAuth flow with a URL-based client_id:"
puts
puts "  1. Client metadata fetched from: #{client_id}"
puts "  2. PKCE with S256 (required for public clients)"
puts "  3. Token exchange without client secret"
puts
puts "Key differences from registered clients:"
puts "  - client_id is an HTTPS URL, not a UUID"
puts "  - Metadata is fetched at runtime (cached by server)"
puts "  - Always treated as a public client"
puts "  - PKCE is mandatory"
puts
puts "For more information, see:"
puts "  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document"
