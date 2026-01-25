# frozen_string_literal: true

# Script to register a client using private_key_jwt authentication.
# With this method, the client authenticates using a signed JWT assertion.
#
# Usage:
#   rails runner script/register_client_with_private_key_jwt.rb

require "net/http"
require "json"
require "uri"
require "openssl"
require "jwt"

# Ensure dynamic registration is enabled
unless TokenAuthority.config.dcr_enabled
  TokenAuthority.config.dcr_enabled = true
  puts "Enabled dynamic client registration for this session.\n\n"
end

base_url = "http://localhost:3000"
register_url = "#{base_url}/oauth/register"

# Generate an RSA key pair for the client
puts "Generating RSA key pair for client..."
rsa_key = OpenSSL::PKey::RSA.generate(2048)
kid = SecureRandom.uuid

# Create JWKS with the public key
jwks = {
  keys: [
    {
      kty: "RSA",
      kid: kid,
      use: "sig",
      alg: "RS256",
      n: Base64.urlsafe_encode64(rsa_key.n.to_s(2), padding: false),
      e: Base64.urlsafe_encode64(rsa_key.e.to_s(2), padding: false)
    }
  ]
}

# Registration request payload
registration_payload = {
  redirect_uris: ["http://localhost:3000/callback"],
  client_name: "Private Key JWT Client",
  token_endpoint_auth_method: "private_key_jwt",
  jwks: jwks, # Inline JWKS (alternatively, use jwks_uri)
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"]
}

puts "=" * 70
puts "RFC 7591 Dynamic Client Registration - private_key_jwt"
puts "=" * 70
puts
puts "With private_key_jwt, the client authenticates using a JWT signed"
puts "with its private key. The authorization server verifies the JWT"
puts "using the client's public key from its registered JWKS."
puts
puts "Registration endpoint: #{register_url}"
puts
puts "Request payload (JWKS included inline):"
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
  puts "SUCCESS! Client registered with private_key_jwt authentication."
  puts "=" * 70
  puts
  puts "Client ID:   #{client_id}"
  puts "Auth Method: #{body["token_endpoint_auth_method"]}"
  puts "Key ID:      #{kid}"
  puts
  puts "Note: No client_secret issued (private_key_jwt uses asymmetric keys)"
  puts
  puts "-" * 70
  puts "Token exchange with private_key_jwt"
  puts "-" * 70
  puts
  puts "To exchange a code for tokens, create a client_assertion JWT:"
  puts

  code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")
  code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")
  redirect_uri = body["redirect_uris"].first

  # Create a sample client_assertion JWT
  now = Time.now.to_i
  assertion_payload = {
    iss: client_id,
    sub: client_id,
    aud: "#{base_url}/oauth/token",
    jti: SecureRandom.uuid,
    iat: now,
    exp: now + 300
  }

  client_assertion = JWT.encode(
    assertion_payload,
    rsa_key,
    "RS256",
    {kid: kid, typ: "JWT"}
  )

  puts "1. Authorize URL:"
  puts
  puts "   #{base_url}/oauth/authorize?client_id=#{client_id}&redirect_uri=#{redirect_uri}&response_type=code&code_challenge=#{code_challenge}&code_challenge_method=S256"
  puts
  puts "2. Client Assertion JWT (valid for 5 minutes):"
  puts
  puts "   #{client_assertion}"
  puts
  puts "3. JWT Payload:"
  puts JSON.pretty_generate(assertion_payload)
  puts
  puts "4. Token exchange request:"
  puts
  puts <<~CURL
    curl -X POST #{base_url}/oauth/token \\
      -d "grant_type=authorization_code" \\
      -d "code=AUTHORIZATION_CODE" \\
      -d "redirect_uri=#{redirect_uri}" \\
      -d "code_verifier=#{code_verifier}" \\
      -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \\
      -d "client_assertion=#{client_assertion}"
  CURL
  puts
  puts "   Code Verifier: #{code_verifier}"
  puts
  puts "-" * 70
  puts "IMPORTANT: Save this private key if you want to use this client!"
  puts "-" * 70
  puts
  puts rsa_key.to_pem
else
  puts
  puts "=" * 70
  puts "FAILED! Registration error."
  puts "=" * 70
  puts
  puts "Error: #{body["error"]}"
  puts "Description: #{body["error_description"]}"
end
