Rails.application.routes.draw do
  token_authority_metadata_routes
  mount TokenAuthority::Engine => "/oauth"

  resources :users, only: %i[new create]

  get "sign-in", to: "sessions#new", as: :sign_in
  post "sign-in", to: "sessions#create"
  delete "sign-out", to: "sessions#destroy", as: :sign_out

  get "callback", to: "callbacks#show", as: :oauth_callback

  root "sessions#new"
end
