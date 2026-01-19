Rails.application.routes.draw do
  mount TokenAuthority::Engine => "/token_authority"
end
