# frozen_string_literal: true

class CallbacksController < ApplicationController
  def show
    @code = params[:code]
    @state = params[:state]
    @error = params[:error]
    @error_description = params[:error_description]
  end
end
