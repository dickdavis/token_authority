# frozen_string_literal: true

require "cgi"
require "json"
require "webrick"

# Configuration
PORT = 4567
REDIRECT_URI = "http://localhost:3000/callback"

puts <<~BANNER
  ============================================================
  Client Metadata Document Server
  ============================================================

  This script serves a client metadata document for testing
  URL-based client identifiers with TokenAuthority.

  SETUP:
  1. Start this server (it's now running on port #{PORT})
  2. In another terminal, expose it via ngrok:

     ngrok http #{PORT}

  3. Copy the ngrok HTTPS URL and enter it below
  ============================================================

BANNER

print "Enter your ngrok HTTPS URL (e.g., https://abc123.ngrok-free.app): "
ngrok_url = gets.chomp.strip

# Remove trailing slash if present
ngrok_url = ngrok_url.chomp("/")

# The client_id URL - metadata will be served at /oauth-client
client_id = "#{ngrok_url}/oauth-client"

# Build the metadata document
metadata = {
  "client_id" => client_id,
  "client_name" => "Test Client (URL-based)",
  "redirect_uris" => [REDIRECT_URI],
  "grant_types" => ["authorization_code", "refresh_token"],
  "response_types" => ["code"],
  "token_endpoint_auth_method" => "none"
}

puts <<~INFO

  Client Metadata Document:
  #{JSON.pretty_generate(metadata)}

  The metadata is now being served at:
  #{client_id}

  To test the OAuth flow, use this client_id in your authorization request:

  http://localhost:3000/oauth/authorize?\\
    client_id=#{CGI.escape(client_id)}&\\
    redirect_uri=#{CGI.escape(REDIRECT_URI)}&\\
    response_type=code&\\
    code_challenge=YOUR_CODE_CHALLENGE&\\
    code_challenge_method=S256&\\
    state=test-state

  Or run the URL-based authorization script:
  bin/rails runner script/mcp_client_metadata_document.rb

  Press Ctrl+C to stop the server.
  ============================================================

INFO

# Create and configure the WEBrick server
server = WEBrick::HTTPServer.new(
  Port: PORT,
  Logger: WEBrick::Log.new($stderr, WEBrick::Log::INFO),
  AccessLog: [[File.open(File::NULL, "w"), WEBrick::AccessLog::COMMON_LOG_FORMAT]]
)

# Serve the metadata document at /oauth-client
server.mount_proc "/oauth-client" do |_req, res|
  res["Content-Type"] = "application/json"
  res["Access-Control-Allow-Origin"] = "*"
  res.body = JSON.generate(metadata)
end

# Handle root path with instructions
server.mount_proc "/" do |_req, res|
  res["Content-Type"] = "text/html"
  res.body = <<~HTML
    <!DOCTYPE html>
    <html>
    <head><title>Client Metadata Server</title></head>
    <body>
      <h1>Client Metadata Document Server</h1>
      <p>The client metadata document is available at:</p>
      <p><a href="/oauth-client">/oauth-client</a></p>
      <h2>Metadata:</h2>
      <pre>#{JSON.pretty_generate(metadata)}</pre>
    </body>
    </html>
  HTML
end

# Graceful shutdown
trap("INT") { server.shutdown }
trap("TERM") { server.shutdown }

server.start
