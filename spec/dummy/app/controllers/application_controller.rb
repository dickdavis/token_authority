# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  helper_method :current_user

  def current_user
    return nil unless (id = session[:user_id])

    @current_user ||= User.find(id)
  end

  private

  def authenticate_user!
    return if current_user.present?

    session[:post_sign_in_url] = request.original_url
    session[:post_sign_in_params] = request.params
    redirect_to main_app.sign_in_path
  end
end
