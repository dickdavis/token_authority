# frozen_string_literal: true

# Confidential Client OAuth Flow with PKCE
#
# This script demonstrates the OAuth flow for a confidential client using PKCE.
# Confidential clients authenticate with client_id and client_secret via HTTP Basic Auth.
#
# Prerequisites:
#   1. Create a confidential client in the database
#   2. Start the Rails server: bin/rails server
#
# Usage:
#   rails runner script/confidential_client_pkce.rb

require "base64"
require "digest"
require "json"
require "net/http"
require "uri"

# =============================================================================
# Configuration
# =============================================================================

BASE_URL = "http://localhost:3000"

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

def http_post_with_basic_auth(url, client_id:, client_secret:, form_data:)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)

  request = Net::HTTP::Post.new(uri.path)
  request.basic_auth(client_id, client_secret)
  request.set_form_data(form_data)

  http.request(request)
end

def generate_pkce
  code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")
  code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")
  {verifier: code_verifier, challenge: code_challenge, method: "S256"}
end

def open_browser(url)
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
# STEP 1: Load Client
# =============================================================================

section "Confidential Client OAuth Flow with PKCE"

client = TokenAuthority::Client.find_by(client_type: "confidential")

unless client
  puts "ERROR: No confidential client found in the database."
  puts
  puts "Create one in rails console:"
  puts '  TokenAuthority::Client.create!(name: "Test Confidential Client", client_type: "confidential", redirect_uris: ["http://localhost:3000/callback"])'
  exit 1
end

client_id = client.public_id
client_secret = client.client_secret

puts "Using client: #{client.name}"
puts "  Client ID:     #{client_id}"
puts "  Client Secret: #{client_secret[0..10]}..."
puts "  Client Type:   #{client.client_type}"

# =============================================================================
# STEP 2: Generate PKCE Parameters
# =============================================================================

section "STEP 1: Generate PKCE Parameters"

puts "PKCE is optional for confidential clients but recommended for additional security."
puts

pkce = generate_pkce

puts "Generated PKCE parameters:"
puts "  Code Verifier:  #{pkce[:verifier]}"
puts "  Code Challenge: #{pkce[:challenge]}"
puts "  Method:         #{pkce[:method]}"

# =============================================================================
# STEP 3: Build Authorization URL
# =============================================================================

section "STEP 2: Authorization Request"

auth_params = {
  client_id: client_id,
  response_type: "code",
  code_challenge: pkce[:challenge],
  code_challenge_method: pkce[:method],
  state: SecureRandom.hex(16)
}

auth_url = "#{BASE_URL}/oauth/authorize?#{URI.encode_www_form(auth_params)}"

puts "Parameters:"
puts "  client_id:             #{client_id}"
puts "  response_type:         code"
puts "  code_challenge:        #{pkce[:challenge]}"
puts "  code_challenge_method: S256"
puts "  state:                 #{auth_params[:state]}"
puts
puts "Note: redirect_uri is optional for confidential clients"
puts
puts "Opening authorization URL in your browser..."

open_browser(auth_url)

# =============================================================================
# STEP 4: Token Exchange
# =============================================================================

section "STEP 3: Token Exchange"

puts "After authorization, you'll be redirected with an authorization code."
puts
puts "For CONFIDENTIAL clients:"
puts "  - Client authenticates via HTTP Basic Auth (client_id:client_secret)"
puts "  - PKCE code_verifier provides additional security"
puts

print "Enter the authorization code: "
authorization_code = gets&.chomp

if authorization_code.nil? || authorization_code.empty?
  puts "No authorization code provided. Exiting."
  exit 0
end

subsection "Exchanging authorization code for tokens..."

token_params = {
  grant_type: "authorization_code",
  code: authorization_code,
  code_verifier: pkce[:verifier]
}

puts "Token endpoint: #{BASE_URL}/oauth/token"
puts "Authentication: HTTP Basic Auth (client_id:client_secret)"
puts
puts "Request parameters:"
token_params.each { |k, v| puts "  #{k}: #{v}" }

response = http_post_with_basic_auth(
  "#{BASE_URL}/oauth/token",
  client_id: client_id,
  client_secret: client_secret,
  form_data: token_params
)
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

section "SUCCESS"

puts "Tokens received:"
puts "  Access Token:  #{access_token[0..50]}..."
puts "  Refresh Token: #{refresh_token[0..50]}..." if refresh_token
puts "  Token Type:    #{token_response["token_type"]}"
puts "  Expires In:    #{token_response["expires_in"]} seconds"
