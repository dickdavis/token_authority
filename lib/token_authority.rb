require "token_authority/version"
require "token_authority/engine"
require "token_authority/configuration"
require "token_authority/errors"
require "token_authority/json_web_token"

module TokenAuthority
  def self.table_name_prefix
    "token_authority_"
  end
end
