# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniAuth::Worldid::RpSigner do
  describe ".hash_to_field" do
    it "empty string -> known field" do
      expect(described_class.hash_to_field("")).to eq(
        "00c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4"
      )
    end

    it '"test_signal" -> known field' do
      expect(described_class.hash_to_field("test_signal")).to eq(
        "00c1636e0a961a3045054c4d61374422c31a95846b8442f0927ad2ff1d6112ed"
      )
    end

    it '"hello" -> known field' do
      expect(described_class.hash_to_field("hello")).to eq(
        "001c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36dea"
      )
    end

    it "raw bytes [1,2,3] -> known field" do
      expect(described_class.hash_to_field([1, 2, 3].pack("C*"))).to eq(
        "00f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92"
      )
    end
  end

  describe ".signature_message" do
    let(:nonce) { ["008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd"].pack("H*") }

    it "without action -> 49-byte message" do
      msg = described_class.signature_message(
        nonce_bytes32: nonce, created_at: 1_700_000_000, expires_at: 1_700_000_300
      )
      expect(msg.unpack1("H*")).to eq(
        "01008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd" \
        "000000006553f100" \
        "000000006553f22c"
      )
    end

    it "with action \"test-action\" -> 81-byte message" do
      msg = described_class.signature_message(
        nonce_bytes32: nonce, created_at: 1_700_000_000, expires_at: 1_700_000_300,
        action: "test-action"
      )
      expect(msg.unpack1("H*")).to eq(
        "01008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd" \
        "000000006553f100" \
        "000000006553f22c" \
        "00aa0ce59768ae5b1c52f07a9387f14f09f277422c0d2f8a268c7bad0c60a46a"
      )
    end
  end

  describe "#sign_request" do
    let(:key) { "abababababababababababababababababababababababababababababababab" }
    let(:signer) { described_class.new(key) }
    let(:deterministic_random) { (0..31).to_a.pack("C*") }

    it "session proof (no action) matches the spec vector" do
      r = signer.sign_request(random: deterministic_random, created_at: 1_700_000_000, ttl: 300)
      expect(r[:nonce]).to eq("0x008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd")
      expect(r[:expires_at]).to eq(1_700_000_300)
      expect(r[:sig]).to eq(
        "0x14f693175773aed912852a601e9c0fd30f2afe2738d31388316232ce6f64ae9e" \
        "4edbfb19d81c4229ba9c9fca78ede4b28956b7ba4415f08d957cbc1b3bdaa4021b"
      )
    end

    it "uniqueness proof (action test-action) matches the spec vector" do
      r = signer.sign_request(action: "test-action", random: deterministic_random,
                              created_at: 1_700_000_000, ttl: 300)
      expect(r[:sig]).to eq(
        "0x05594adb6c1495768a38d523d7d6ee6356b2c31231919198794ed022ade7d08f" \
        "73753f83bd167067d99c9b969d28e9222315837c66af25867b041273a6d5056f1b"
      )
    end

    it "accepts 0x-prefixed keys" do
      expect { described_class.new("0x" + key) }.not_to raise_error
    end

    it "rejects malformed keys" do
      expect { described_class.new("abcd") }.to raise_error(OmniAuth::Worldid::RpSigner::Error)
    end
  end
end
