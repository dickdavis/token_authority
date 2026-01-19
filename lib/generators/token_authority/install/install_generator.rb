# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module TokenAuthority
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      class_option :user_table_name,
        type: :string,
        default: "users",
        desc: "Name of the user table in your application"

      class_option :user_foreign_key_type,
        type: :string,
        default: "bigint",
        desc: "Type of the user table's primary key (bigint, uuid, integer)"

      def create_migration_file
        migration_template(
          "create_token_authority_tables.rb.erb",
          "db/migrate/create_token_authority_tables.rb"
        )
      end

      private

      def user_table_name
        options[:user_table_name]
      end

      def user_foreign_key_type
        options[:user_foreign_key_type]
      end

      def migration_version
        "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
      end
    end
  end
end
