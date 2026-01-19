# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_01_19_233307) do
  create_table "token_authority_authorization_grants", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.string "public_id", null: false
    t.boolean "redeemed", default: false, null: false
    t.integer "token_authority_client_id", null: false
    t.datetime "updated_at", null: false
    t.bigint "user_id"
    t.index ["public_id"], name: "index_token_authority_authorization_grants_on_public_id", unique: true
    t.index ["token_authority_client_id"], name: "index_ta_auth_grants_on_client_id"
    t.index ["user_id"], name: "index_ta_auth_grants_on_user_id"
  end

  create_table "token_authority_challenges", force: :cascade do |t|
    t.string "code_challenge"
    t.string "code_challenge_method", default: "S256"
    t.datetime "created_at", null: false
    t.string "redirect_uri"
    t.integer "token_authority_authorization_grant_id", null: false
    t.datetime "updated_at", null: false
    t.index ["token_authority_authorization_grant_id"], name: "index_ta_challenges_on_auth_grant_id"
  end

  create_table "token_authority_clients", force: :cascade do |t|
    t.bigint "access_token_duration", default: 300, null: false
    t.string "client_secret_id"
    t.string "client_type", default: "confidential", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.string "public_id", null: false
    t.string "redirect_uri", null: false
    t.bigint "refresh_token_duration", default: 1209600, null: false
    t.datetime "updated_at", null: false
    t.index ["client_secret_id"], name: "index_token_authority_clients_on_client_secret_id", unique: true
    t.index ["public_id"], name: "index_token_authority_clients_on_public_id", unique: true
  end

  create_table "token_authority_sessions", force: :cascade do |t|
    t.string "access_token_jti", null: false
    t.datetime "created_at", null: false
    t.string "refresh_token_jti", null: false
    t.string "status", default: "created", null: false
    t.integer "token_authority_authorization_grant_id"
    t.datetime "updated_at", null: false
    t.index ["access_token_jti"], name: "index_token_authority_sessions_on_access_token_jti", unique: true
    t.index ["refresh_token_jti"], name: "index_token_authority_sessions_on_refresh_token_jti", unique: true
    t.index ["token_authority_authorization_grant_id"], name: "index_ta_sessions_on_auth_grant_id"
  end

  create_table "users", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email"
    t.string "first_name"
    t.string "last_name"
    t.string "password_digest"
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_users_on_email", unique: true
  end

  add_foreign_key "token_authority_authorization_grants", "token_authority_clients"
  add_foreign_key "token_authority_authorization_grants", "users"
  add_foreign_key "token_authority_challenges", "token_authority_authorization_grants"
  add_foreign_key "token_authority_sessions", "token_authority_authorization_grants"
end
