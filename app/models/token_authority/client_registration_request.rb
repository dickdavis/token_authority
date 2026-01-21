# frozen_string_literal: true

module TokenAuthority
  ##
  # Service object for validating and processing dynamic client registration requests (RFC 7591)
  class ClientRegistrationRequest
    include ActiveModel::Model
    include ActiveModel::Validations

    VALID_AUTH_METHODS = TokenAuthority::Client::SUPPORTED_AUTH_METHODS

    attr_accessor :redirect_uris,
      :token_endpoint_auth_method,
      :grant_types,
      :response_types,
      :client_name,
      :client_uri,
      :logo_uri,
      :tos_uri,
      :policy_uri,
      :contacts,
      :scope,
      :jwks_uri,
      :jwks,
      :software_id,
      :software_version,
      :software_statement

    validates :redirect_uris, presence: true
    validate :redirect_uris_are_valid
    validate :token_endpoint_auth_method_is_allowed
    validate :grant_types_are_allowed
    validate :response_types_are_consistent
    validate :contacts_are_valid_emails
    validate :jwks_and_jwks_uri_mutually_exclusive
    validate :jwks_required_for_private_key_jwt
    validate :software_statement_is_valid

    def initialize(attributes = {})
      super
      @token_endpoint_auth_method ||= "client_secret_basic"
      @grant_types ||= ["authorization_code"]
      @response_types ||= ["code"]
    end

    def create_client!
      raise TokenAuthority::InvalidClientMetadataError, errors.full_messages.join(", ") unless valid?

      merged_attrs = merge_software_statement_claims
      build_client(merged_attrs).tap(&:save!)
    end

    private

    def redirect_uris_are_valid
      return if redirect_uris.blank?
      return unless redirect_uris.is_a?(Array)

      redirect_uris.each do |uri|
        parsed = URI.parse(uri)
        unless parsed.is_a?(URI::HTTP) || parsed.is_a?(URI::HTTPS)
          errors.add(:redirect_uris, "contains invalid URI scheme: #{uri}")
          break
        end
      rescue URI::InvalidURIError
        errors.add(:redirect_uris, "contains invalid URI: #{uri}")
        break
      end
    end

    def token_endpoint_auth_method_is_allowed
      return if token_endpoint_auth_method.blank?

      allowed = TokenAuthority.config.rfc_7591_allowed_token_endpoint_auth_methods
      unless allowed.include?(token_endpoint_auth_method)
        errors.add(:token_endpoint_auth_method, "is not allowed: #{token_endpoint_auth_method}")
      end
    end

    def grant_types_are_allowed
      return if grant_types.blank?
      return unless grant_types.is_a?(Array)

      allowed = TokenAuthority.config.rfc_7591_allowed_grant_types
      disallowed = grant_types - allowed
      errors.add(:grant_types, "contains disallowed types: #{disallowed.join(", ")}") if disallowed.any?
    end

    def response_types_are_consistent
      return if response_types.blank? || grant_types.blank?

      if grant_types.include?("authorization_code") && !response_types.include?("code")
        errors.add(:response_types, "must include 'code' when grant_types includes 'authorization_code'")
      end
    end

    def contacts_are_valid_emails
      return if contacts.blank?
      return unless contacts.is_a?(Array)

      email_regex = /\A[\w+\-.]+@[a-z\d-]+(\.[a-z\d-]+)*\.[a-z]+\z/i
      contacts.each do |email|
        unless email.match?(email_regex)
          errors.add(:contacts, "contains invalid email: #{email}")
          break
        end
      end
    end

    def jwks_and_jwks_uri_mutually_exclusive
      if jwks.present? && jwks_uri.present?
        errors.add(:base, "jwks and jwks_uri are mutually exclusive")
      end
    end

    def jwks_required_for_private_key_jwt
      return unless token_endpoint_auth_method == "private_key_jwt"

      if jwks.blank? && jwks_uri.blank?
        errors.add(:base, "jwks or jwks_uri is required when token_endpoint_auth_method is private_key_jwt")
      end
    end

    def software_statement_is_valid
      return if software_statement.blank?

      begin
        @parsed_software_statement = parse_software_statement
      rescue TokenAuthority::InvalidSoftwareStatementError => e
        errors.add(:software_statement, e.message)
      rescue TokenAuthority::UnapprovedSoftwareStatementError => e
        errors.add(:software_statement, e.message)
      end
    end

    def parse_software_statement
      jwks = TokenAuthority.config.rfc_7591_software_statement_jwks
      if jwks.present?
        SoftwareStatement.decode_and_verify(software_statement, jwks: jwks)
      elsif TokenAuthority.config.rfc_7591_software_statement_required
        raise TokenAuthority::UnapprovedSoftwareStatementError
      else
        SoftwareStatement.decode(software_statement)
      end
    end

    def merge_software_statement_claims
      base_attrs = registration_attributes
      return base_attrs unless @parsed_software_statement

      # Software statement claims take precedence per RFC 7591
      @parsed_software_statement.claims.compact.merge(base_attrs.compact) do |_key, ss_val, req_val|
        ss_val.present? ? ss_val : req_val
      end
    end

    def registration_attributes
      {
        redirect_uris: redirect_uris,
        token_endpoint_auth_method: token_endpoint_auth_method,
        grant_types: grant_types,
        response_types: response_types,
        client_name: client_name,
        client_uri: client_uri,
        logo_uri: logo_uri,
        tos_uri: tos_uri,
        policy_uri: policy_uri,
        contacts: contacts,
        scope: scope,
        jwks_uri: jwks_uri,
        jwks: jwks,
        software_id: software_id,
        software_version: software_version
      }
    end

    def build_client(attrs)
      client_type = (attrs[:token_endpoint_auth_method] == "none") ? "public" : "confidential"

      TokenAuthority::Client.new(
        name: attrs[:client_name] || "Dynamic Client",
        redirect_uris: attrs[:redirect_uris],
        client_type: client_type,
        token_endpoint_auth_method: attrs[:token_endpoint_auth_method] || "client_secret_basic",
        grant_types: attrs[:grant_types],
        response_types: attrs[:response_types],
        scope: attrs[:scope],
        client_uri: attrs[:client_uri],
        logo_uri: attrs[:logo_uri],
        tos_uri: attrs[:tos_uri],
        policy_uri: attrs[:policy_uri],
        contacts: attrs[:contacts],
        jwks_uri: attrs[:jwks_uri],
        jwks: attrs[:jwks],
        software_id: attrs[:software_id],
        software_version: attrs[:software_version],
        software_statement: software_statement,
        dynamically_registered: true
      )
    end
  end
end
