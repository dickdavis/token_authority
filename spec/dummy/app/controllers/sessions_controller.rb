# frozen_string_literal: true

class SessionsController < ApplicationController
  def new
  end

  def create
    user = User.find_by(email: params[:email])

    if user&.authenticate(params[:password])
      session[:user_id] = user.id.to_s
      redirect_to url_for_sign_in_redirect, notice: t(".login_success")
    else
      flash.now.alert = t(".login_failure")
      render "sessions/new"
    end
  end

  def destroy
    session.delete(:user_id)
    redirect_to root_path
  end

  private

  def url_for_sign_in_redirect
    return root_path unless (post_sign_in_url = session.delete(:post_sign_in_url))

    url = URI(post_sign_in_url)
    if (params_for_query = session.delete(:post_sign_in_params))
      url.query = URI.encode_www_form(
        params_for_query.collect { |key, value| [key.to_s, value] }
      )
    end

    url.to_s
  rescue URI::InvalidURIError, ArgumentError
    root_path
  end
end
