TokenAuthority::Engine.routes.draw do
  get "authorize", to: "authorizations#authorize"
  resources :authorization_grants, path: "authorization-grants", only: %i[new create]

  # Token endpoint with grant_type constraints
  constraints(TokenAuthority::Routing::GrantTypeConstraint.new("refresh_token")) do
    post "token", to: "sessions#refresh", as: :refresh_session
  end

  constraints(TokenAuthority::Routing::GrantTypeConstraint.new("authorization_code")) do
    post "token", to: "sessions#token", as: :create_session
  end

  post "token", to: "sessions#unsupported_grant_type", as: :unsupported_grant_type

  # Revoke endpoint with token_type_hint constraints
  constraints(TokenAuthority::Routing::TokenTypeHintConstraint.new("access_token")) do
    post "revoke", to: "sessions#revoke_access_token", as: :revoke_access_token
  end

  constraints(TokenAuthority::Routing::TokenTypeHintConstraint.new("refresh_token")) do
    post "revoke", to: "sessions#revoke_refresh_token", as: :revoke_refresh_token
  end

  post "revoke", to: "sessions#revoke"
end
