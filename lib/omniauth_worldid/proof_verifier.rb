# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module OmniAuth
  module Worldid
    # Verifies World ID 4.0 (and legacy 3.0) proofs against the Developer
    # Portal verification service:
    #
    #   POST https://developer.world.org/api/v4/verify/{rp_id}
    #
    # The request body is the IDKit result payload forwarded as-is. Returns a
    # normalized Result struct.
    class ProofVerifier
      VERIFY_BASE_URL = "https://developer.world.org"

      Error = Class.new(StandardError)
      VerificationFailed = Class.new(Error)

      Result = Struct.new(
        :verified?, :protocol_version, :identifier, :nullifier, :session_id,
        :action, :environment, :raw,
        keyword_init: true
      )

      def initialize(rp_id:, base_url: VERIFY_BASE_URL, open_timeout: 10, read_timeout: 20, http: nil)
        @rp_id = rp_id
        @base_url = base_url
        @open_timeout = open_timeout
        @read_timeout = read_timeout
        @http = http
      end

      def verify(idkit_result)
        uri = URI.join(@base_url.end_with?("/") ? @base_url : @base_url + "/", "api/v4/verify/#{@rp_id}")
        response = post_json(uri, idkit_result)
        parse_response(response)
      end

      private

      def post_json(uri, payload)
        http = @http || Net::HTTP.start(
          uri.host, uri.port,
          use_ssl: uri.scheme == "https",
          open_timeout: @open_timeout,
          read_timeout: @read_timeout
        )
        request = Net::HTTP::Post.new(uri.request_uri)
        request["content-type"] = "application/json"
        request.body = JSON.generate(payload)
        own = @http.nil?
        begin
          http.request(request)
        ensure
          http.finish if own && http.started?
        end
      end

      def parse_response(response)
        body = safe_json(response.body)
        if response.code.to_i == 200 && body.is_a?(Hash)
          build_success(body)
        else
          raise VerificationFailed, error_message(body, response.code)
        end
      end

      def build_success(body)
        results = Array(body["results"])
        first = results.find { |r| r["success"] } || results.first || {}
        Result.new(
          verified?: true,
          protocol_version: body.dig("results", 0, "protocol_version") || body["protocol_version"],
          identifier: first["identifier"],
          nullifier: body["nullifier"] || first["nullifier"],
          session_id: body["session_id"],
          action: body["action"],
          environment: body["environment"],
          raw: body
        )
      end

      def error_message(body, code)
        detail = body.is_a?(Hash) ? (body["detail"] || body["code"] || body["message"]) : nil
        "World ID verification failed (HTTP #{code})#{detail ? ": #{detail}" : ""}"
      end

      def safe_json(body)
        JSON.parse(body)
      rescue StandardError
        {} 
      end
    end
  end
end
