# frozen_string_literal: true

require "digest"

code_verifier = SecureRandom.base64(55).tr("+/", "-_").tr("=", "")
code_challenge = Digest::SHA256.base64digest(code_verifier).tr("+/", "-_").tr("=", "")
client = TokenAuthority::Client.where(client_type: "confidential").first
client_id = client.public_id
client_secret = client.client_secret

puts <<~TEXT
  Save the code verifier for the token exchange request.

  code_verifier: #{code_verifier}

  Open this URL in your browser and sign in to approve the authorization:

  http://localhost:3000/oauth/authorize?client_id=#{client_id}&response_type=code&code_challenge=#{code_challenge}&code_challenge_method=S256

  Client credentials:
  client_id: #{client_id}
  client_secret: #{client_secret}
TEXT
