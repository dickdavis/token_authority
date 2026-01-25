Rails.application.routes.draw do
  token_authority_auth_server_routes
  token_authority_protected_resource_route

  namespace :api do
    namespace :v1 do
      get "users/current", to: "users#current"
    end
  end

  resources :users, only: %i[new create]

  get "sign-in", to: "sessions#new", as: :sign_in
  post "sign-in", to: "sessions#create"
  delete "sign-out", to: "sessions#destroy", as: :sign_out

  get "callback", to: "callbacks#show", as: :oauth_callback

  root "sessions#new"
end
