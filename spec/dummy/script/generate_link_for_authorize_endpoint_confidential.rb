# frozen_string_literal: true

client = TokenAuthority::Client.where(client_type: "confidential").first
client_id = client.public_id
client_secret = client.client_secret

puts <<~TEXT
  Open this URL in your browser and sign in to approve the authorization:

  http://localhost:3000/oauth/authorize?response_type=code

TEXT

print "Enter the authorization code: "
authorization_code = gets.chomp

puts <<~TEXT

  Exchange the authorization code for tokens:

  curl -X POST http://localhost:3000/oauth/token \\
    -u "#{client_id}:#{client_secret}" \\
    -d "grant_type=authorization_code" \\
    -d "code=#{authorization_code}"
TEXT
