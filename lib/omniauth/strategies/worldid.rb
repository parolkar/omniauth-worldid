# frozen_string_literal: true

require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Worldid < OmniAuth::Strategies::OAuth2
      option :name, "worldid"

      option :client_options, {
        site: "https://id.worldcoin.org",
        authorize_url: "https://id.worldcoin.org/authorize",
        token_url: "https://id.worldcoin.org/token"
      }

      option :scope, "openid profile email"

      # Minimum verification level: "orb" or "device"
      # Set to "orb" to reject device-only verifications
      option :min_verification_level, nil

      option :authorize_params, {}
      option :token_params, {}

      uid { raw_info["sub"] }

      info do
        {
          name: raw_info["name"],
          email: raw_info["email"],
          given_name: raw_info["given_name"],
          family_name: raw_info["family_name"],
          verification_level: verification_level,
          orb_verified: orb_verified?
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def raw_info
        @raw_info ||= access_token.get("/userinfo").parsed
      end

      # Returns "orb" or "device"
      def verification_level
        v1 = raw_info.dig("https://id.worldcoin.org/v1", "verification_level")
        return v1 if v1

        # Fallback to beta claim
        raw_info.dig("https://id.worldcoin.org/beta", "credential_type")
      end

      # True if user was verified at a physical Orb
      def orb_verified?
        verification_level == "orb"
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def authorize_params
        super.tap do |params|
          params[:scope] = options.scope
          params[:response_type] = "code"
        end
      end

      private

      def callback_phase
        level = verification_level
        min = options.min_verification_level

        if min == "orb" && level != "orb"
          fail!(:orb_verification_required,
            OmniAuth::Error.new("Orb verification required, got: #{level}"))
        else
          super
        end
      rescue StandardError => e
        fail!(:worldid_error, e)
      end
    end
  end
end
