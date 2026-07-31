# frozen_string_literal: true

require "spec_helper"
require "rack/test"
require "webmock/rspec"
require "json"
require "rack/session/cookie"

RSpec.describe OmniAuth::Strategies::WorldidV4 do
  include Rack::Test::Methods

  let(:rp_id) { "rp_test9" }
  let(:signing_key) { "cd" * 32 }
  let(:verify_endpoint) { "https://developer.world.org/api/v4/verify/#{rp_id}" }
  let(:session_secret) { "s" * 64 }

  # The request phase is a JSON endpoint that asks the client to generate a proof;
  # OmniAuth's authenticity protection is for HTML-browser sign-in forms and not
  # applicable to this API-style strategy.
  def with_request_validation_disabled
    orig = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    yield
  ensure
    OmniAuth.config.request_validation_phase = orig
  end

  let(:inner) do
    lambda do |env|
      auth = env["omniauth.auth"]
      body =
        if auth
          { uid: auth.uid, info: auth.info, extra: auth.extra.to_h }
        else
          { no_auth: true }
        end
      [200, { "content-type" => "application/json" }, [JSON.generate(body)]]
    end
  end

  let(:app) do
    rid = rp_id
    skey = signing_key
    act = "sign-in"
    Rack::Session::Cookie.new(
      OmniAuth::Builder.new do
        provider :worldid_v4, rp_id: rid, signing_key: skey, action: act
        run lambda { |env|
          auth = env["omniauth.auth"]
          body = auth ? { uid: auth.uid, info: auth.info.to_h, extra: auth.extra.to_h } : { no_auth: true }
          [200, { "content-type" => "application/json" }, [JSON.generate(body)]]
        }
      end.to_app,
      secret: session_secret
    )
  end

  it "emits a signed RP context on POST /auth/worldid_v4" do
    with_request_validation_disabled do
      post "/auth/worldid_v4"
    end
    expect(last_response.status).to eq(200)
    body = JSON.parse(last_response.body)
    expect(body["sig"]).to start_with("0x")
    expect(body["nonce"]).to start_with("0x")
    expect(body["rp_id"]).to eq(rp_id)
    expect(body["action"]).to eq("sign-in")
    expect(body["expires_at"] - body["created_at"]).to eq(300)
  end

  it "verifies a valid proof on POST /auth/worldid_v4/callback" do
    stub_request(:post, verify_endpoint).to_return(
      status: 200,
      body: JSON.generate(
        success: true,
        action: "sign-in",
        environment: "production",
        session_id: "session_test_123",
        results: [{ "identifier" => "proof_of_human", "success" => true, "nullifier" => "0xhuman_nullifier" }]
      )
    )

    post "/auth/worldid_v4/callback",
      JSON.generate(
        protocol_version: "4.0", nonce: "0xnonce", action: "sign-in",
        responses: [{ identifier: "proof_of_human", issuer_schema_id: 1,
                      nullifier: "0xhuman_nullifier", expires_at_min: 49012345,
                      proof: %w[0x1 0x2 0x3 0x4 0x5] }]
      ),
      { "CONTENT_TYPE" => "application/json" }

    expect(last_response.status).to eq(200)
    auth = JSON.parse(last_response.body)
    expect(auth["uid"]).to eq("0xhuman_nullifier")
    expect(auth.dig("info", "identifier")).to eq("proof_of_human")
    expect(auth.dig("info", "human_verified")).to be(true)
    expect(auth.dig("extra", "session_id")).to eq("session_test_123")
  end

  it "rejects the callback when verification fails" do
    stub_request(:post, verify_endpoint).to_return(
      status: 400,
      body: JSON.generate(success: false, code: "all_verifications_failed", detail: "bad proof")
    )

    post "/auth/worldid_v4/callback",
      JSON.generate(protocol_version: "4.0", nonce: "0xn", action: "sign-in",
                    responses: [{ "identifier" => "proof_of_human" }]),
      { "CONTENT_TYPE" => "application/json" }

    expect(last_response.status).to eq(302)
    expect(last_response["Location"]).to include("failure")
  end
end
