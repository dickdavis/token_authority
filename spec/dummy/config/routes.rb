Rails.application.routes.draw do
  mount TokenAuthority::Engine => "/token_authority"

  resources :users, only: %i[new create]

  get "sign-in", to: "sessions#new", as: :sign_in
  post "sign-in", to: "sessions#create"
  delete "sign-out", to: "sessions#destroy", as: :sign_out

  root "sessions#new"
end
