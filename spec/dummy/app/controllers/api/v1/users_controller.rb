# frozen_string_literal: true

module Api
  module V1
    class UsersController < ActionController::API
      include TokenAuthority::TokenAuthentication

      before_action :require_read_scope

      def current
        render json: {id: token_user.id, email: token_user.email}, status: :ok
      end

      private

      def require_read_scope
        return if token_scope.include?("read")

        render json: {error: "insufficient_scope", required: "read", granted: token_scope}, status: :forbidden
      end
    end
  end
end
