# frozen_string_literal: true

class CreateUsers < ActiveRecord::Migration[7.0]
  def change
    create_table :users do |table|
      table.string :first_name
      table.string :last_name
      table.string :email, index: {unique: true}
      table.string :password_digest

      table.timestamps
    end
  end
end
