# frozen_string_literal: true

require "securerandom"
require "eth"

module OmniAuth
  module Worldid
    # Generates World ID 4.0 Relying Party (RP) signatures.
    #
    # An RP signature proves that a proof request originated from your backend
    # (not the client). It is an EIP-191 recoverable secp256k1 signature over a
    # 49-byte message (session proofs) or 81-byte message (uniqueness proofs
    # with an action):
    #
    #   msg[0]      = 0x01
    #   msg[1..32]  = nonce  (32-byte field element, hash_to_field(random))
    #   msg[33..40] = created_at (u64 big-endian)
    #   msg[41..48] = expires_at (u64 big-endian)
    #   msg[49..80] = hash_to_field(action)   (only when action is present)
    #
    # digest = keccak256( "\x19Ethereum Signed Message:\n<len>" + msg )
    #
    # IMPORTANT: this uses Keccak-256, not NIST SHA3-256 (different padding).
    class RpSigner
      Error = Class.new(StandardError)

      DEFAULT_TTL = 300

      # Hash bytes into a 32-byte field element: keccak256, big-endian >> 8.
      # Result always has a leading 0x00 byte.
      def self.hash_to_field(bytes)
        digest = Eth::Util.keccak256(bytes)
        (digest.unpack1("H*").to_i(16) >> 8).to_s(16).rjust(64, "0")
      end

      def initialize(signing_key_hex)
        hex = signing_key_hex.to_s.sub(/\A0x/i, "")
        raise Error, "signing key must be 32 hex bytes (64 hex chars)" unless hex.length == 64

        @key_hex = hex
      end

      # Sign a request. Returns { sig:, nonce:, created_at:, expires_at: } where
      # sig and nonce are 0x-prefixed hex and the timestamps are integers.
      #
      # `random` is injectable for deterministic spec-vector testing.
      def sign_request(action: nil, ttl: DEFAULT_TTL, random: nil, created_at: nil)
        random ||= SecureRandom.random_bytes(32)
        nonce_hex = self.class.hash_to_field(random)
        created_at ||= Time.now.to_i
        expires_at = created_at + ttl.to_i

        message = self.class.signature_message(
          nonce_bytes32: [nonce_hex].pack("H*"),
          created_at: created_at,
          expires_at: expires_at,
          action: action
        )

        raw_sig = Eth::Key.new(priv: @key_hex).personal_sign(message)
        signature = raw_sig.start_with?("0x") ? raw_sig : "0x" + raw_sig

        { sig: signature, nonce: "0x" + nonce_hex, created_at: created_at, expires_at: expires_at }
      end

      def self.signature_message(nonce_bytes32:, created_at:, expires_at:, action: nil)
        msg = +"\x01".b
        msg << nonce_bytes32
        msg << [created_at].pack("Q>")
        msg << [expires_at].pack("Q>")
        msg << [hash_to_field(action.to_s.encode("UTF-8"))].pack("H*") if action
        msg
      end
    end
  end
end
