# frozen_string_literal: true

class User < ApplicationRecord
  has_secure_password

  validates :first_name, presence: true, length: {maximum: 255}
  validates :last_name, presence: true, length: {maximum: 255}
  validates :email,
    presence: true,
    length: {maximum: 255},
    uniqueness: {case_sensitive: false},
    format: {with: /\A([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\z/i}
end
