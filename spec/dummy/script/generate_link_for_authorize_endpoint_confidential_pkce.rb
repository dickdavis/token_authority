# frozen_string_literal: true

require "digest"

code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")
code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")
client = TokenAuthority::Client.where(client_type: "confidential").first
client_id = client.public_id
client_secret = client.client_secret
redirect_uri = client.redirect_uri

puts <<~TEXT
  Open this URL in your browser and sign in to approve the authorization:

  http://localhost:3000/oauth/authorize?client_id=#{client_id}&redirect_uri=#{redirect_uri}&response_type=code&code_challenge=#{code_challenge}&code_challenge_method=S256

TEXT

print "Enter the authorization code: "
authorization_code = gets.chomp

puts <<~TEXT

  Exchange the authorization code for tokens:

  curl -X POST http://localhost:3000/oauth/token \\
    -u "#{client_id}:#{client_secret}" \\
    -d "grant_type=authorization_code" \\
    -d "code=#{authorization_code}" \\
    -d "redirect_uri=#{redirect_uri}" \\
    -d "code_verifier=#{code_verifier}"
TEXT
