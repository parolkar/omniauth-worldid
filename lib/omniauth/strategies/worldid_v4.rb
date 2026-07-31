# frozen_string_literal: true

require "omniauth-worldid"

module OmniAuth
  module Strategies
    # OmniAuth strategy for World ID 4.0 (ZK proof-of-human verification).
    #
    # Unlike the legacy OIDC flow, v4 is request/response: the client generates
    # a zero-knowledge proof with IDKit (via World App) and POSTs it back here;
    # we verify it server-side against the Developer Portal and expose the
    # resulting human-nullifier as the uid.
    #
    #   use OmniAuth::Builder do
    #     provider :worldid_v4,
    #       rp_id: ENV["WORLDID_RP_ID"],
    #       signing_key: ENV["WORLDID_SIGNING_KEY"],
    #       action: "sign-in"
    #   end
    #
    # The request phase (GET/POST /auth/worldid_v4) emits the RP context
    # (sig/nonce/created_at/expires_at) the client needs as JSON. The callback
    # phase (POST /auth/worldid_v4/callback) verifies a posted IDKit result.
    class WorldidV4
      include OmniAuth::Strategy

      option :name, "worldid_v4"

      option :rp_id, nil
      option :signing_key, nil        # 32-byte hex (0x prefix acceptable)
      option :action, nil             # set for uniqueness proofs; nil = session proof
      option :ttl, 300
      option :verify_base_url, OmniAuth::Worldid::ProofVerifier::VERIFY_BASE_URL

      uid { verify_result&.nullifier || verify_result&.session_id }

      info do
        {
          identifier: verify_result&.identifier,
          protocol_version: verify_result&.protocol_version,
          environment: verify_result&.environment,
          human_verified: !!verify_result&.verified?
        }
      end

      extra do
        {
          session_id: verify_result&.session_id,
          action: verify_result&.action,
          raw: verify_result&.raw
        }
      end

      def callback_phase
        payload = idkit_payload
        fail!(:invalid_credentials, OmniAuth::Worldid::ProofVerifier::Error.new("missing proof payload")) unless payload

        @verify_result = OmniAuth::Worldid::ProofVerifier
          .new(rp_id: options.rp_id, base_url: options.verify_base_url)
          .verify(payload)

        env["omniauth.auth"] = auth_hash
        call_app!
      rescue OmniAuth::Worldid::ProofVerifier::Error => e
        fail!(:verification_failed, e)
      end

      def request_phase
        signer = OmniAuth::Worldid::RpSigner.new(options.signing_key)
        signed = signer.sign_request(action: options.action, ttl: options.ttl)
        Rack::Response.new(
          [{ sig: signed[:sig], nonce: signed[:nonce], created_at: signed[:created_at],
             expires_at: signed[:expires_at], action: options.action, rp_id: options.rp_id }.to_json],
          200,
          {"content-type" => "application/json"}
        ).finish
      rescue OmniAuth::Worldid::RpSigner::Error => e
        fail!(:signing_error, e)
      end

      private

      attr_reader :verify_result

      def idkit_payload
        body = request.body&.read
        request.body&.rewind
        return nil if body.nil? || body.empty?

        parsed = JSON.parse(body)
        parsed.key?("protocol_version") ? parsed : (parsed["idkit_response"] || parsed["proof"])
      rescue JSON::ParserError
        nil
      end
    end
  end
end
