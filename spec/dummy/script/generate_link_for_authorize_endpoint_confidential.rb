# frozen_string_literal: true

require "digest"

client = TokenAuthority::Client.where(client_type: "confidential").first
client_id = client.public_id
client_secret = client.client_secret

puts <<~TEXT
  Open this URL in your browser and sign in to approve the authorization:

  http://localhost:3000/oauth/authorize?response_type=code

  Client credentials:
  client_id: #{client_id}
  client_secret: #{client_secret}
TEXT
