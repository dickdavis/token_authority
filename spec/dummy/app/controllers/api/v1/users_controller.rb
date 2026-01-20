# frozen_string_literal: true

module Api
  module V1
    class UsersController < ActionController::API
      include TokenAuthority::TokenAuthentication

      def current
        user = user_from_token
        render json: {id: user.id, email: user.email}, status: :ok
      end
    end
  end
end
