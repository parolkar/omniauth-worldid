# frozen_string_literal: true

require "spec_helper"
require "webmock/rspec"

RSpec.describe OmniAuth::Worldid::ProofVerifier do
  let(:verifier) { described_class.new(rp_id: "rp_42") }
  let(:endpoint) { "https://developer.world.org/api/v4/verify/rp_42" }
  let(:payload) do
    {
      protocol_version: "4.0",
      nonce: "0xabc",
      responses: [{
        identifier: "proof_of_human",
        issuer_schema_id: 1,
        nullifier: "0xnullifier123",
        expires_at_min: 49012345,
        proof: %w[0x1 0x2 0x3 0x4 0x5]
      }]
    }
  end

  it "posts the payload as-is to the v4 verify endpoint" do
    stub = stub_request(:post, endpoint)
      .with(body: JSON.generate(payload), headers: { "content-type" => "application/json" })
      .to_return(status: 200, body: JSON.generate(
        success: true,
        action: "sign-in",
        environment: "production",
        results: [{ identifier: "proof_of_human", success: true, nullifier: "0xnullifier123" }]
      ))

    result = verifier.verify(payload)
    expect(stub).to have_been_requested
    expect(result.verified?).to be(true)
  end

  it "maps nullifier, session_id and identifier into a Result" do
    stub_request(:post, endpoint).to_return(status: 200, body: JSON.generate(
      success: true,
      session_id: "session_abc123",
      results: [{ identifier: "proof_of_human", success: true, nullifier: "0xn" }]
    ))
    r = verifier.verify(payload)
    expect(r.nullifier).to eq("0xn")
    expect(r.session_id).to eq("session_abc123")
    expect(r.identifier).to eq("proof_of_human")
  end

  it "raises VerificationFailed on a 400 response" do
    stub_request(:post, endpoint).to_return(status: 400, body: JSON.generate(
      success: false, code: "all_verifications_failed", detail: "All proof verifications failed."
    ))
    expect { verifier.verify(payload) }
      .to raise_error(OmniAuth::Worldid::ProofVerifier::VerificationFailed, /HTTP 400/)
  end

  it "raises VerificationFailed on a 404" do
    stub_request(:post, endpoint).to_return(status: 404, body: "{}")
    expect { verifier.verify(payload) }
      .to raise_error(OmniAuth::Worldid::ProofVerifier::VerificationFailed, /HTTP 404/)
  end
end
