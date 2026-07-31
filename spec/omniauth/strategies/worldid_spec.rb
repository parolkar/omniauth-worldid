# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniAuth::Strategies::Worldid do
  let(:app) { ->(env) { [200, {}, ["OK"]] } }
  let(:strategy) { described_class.new(app, "client_id", "client_secret") }

  describe "client options" do
    subject { strategy.options.client_options }

    it "sets the site to World ID" do
      expect(subject.site).to eq("https://id.worldcoin.org")
    end

    it "sets the authorize URL" do
      expect(subject.authorize_url).to eq("https://id.worldcoin.org/authorize")
    end

    it "sets the token URL" do
      expect(subject.token_url).to eq("https://id.worldcoin.org/token")
    end
  end

  describe "default scope" do
    it "includes openid profile email" do
      expect(strategy.options.scope).to eq("openid profile email")
    end
  end

  describe "name" do
    it "defaults to worldid" do
      expect(strategy.options.name).to eq("worldid")
    end
  end

  describe "#verification_level" do
    context "with v1 claims" do
      before do
        allow(strategy).to receive(:raw_info).and_return(
          "https://id.worldcoin.org/v1" => { "verification_level" => "orb" }
        )
      end

      it "returns orb" do
        expect(strategy.verification_level).to eq("orb")
      end
    end

    context "with beta claims" do
      before do
        allow(strategy).to receive(:raw_info).and_return(
          "https://id.worldcoin.org/beta" => { "credential_type" => "device" }
        )
      end

      it "falls back to beta credential_type" do
        expect(strategy.verification_level).to eq("device")
      end
    end
  end

  describe "#orb_verified?" do
    it "returns true when verification level is orb" do
      allow(strategy).to receive(:verification_level).and_return("orb")
      expect(strategy.orb_verified?).to be true
    end

    it "returns false when verification level is device" do
      allow(strategy).to receive(:verification_level).and_return("device")
      expect(strategy.orb_verified?).to be false
    end
  end

  describe "#callback_phase visibility" do
    it "is public so OmniAuth can invoke it as a method" do
      expect(described_class.public_method_defined?(:callback_phase)).to be true
      expect(described_class.private_method_defined?(:callback_phase)).to be false
    end
  end

  describe "info hash" do
    before do
      allow(strategy).to receive(:raw_info).and_return(
        "sub" => "0x2ae86d6d747702b3b2c81811cd2b39875e8fa6b780ee4a207bdc203a7860b535",
        "name" => "World ID User",
        "email" => "0x2ae86d@id.worldcoin.org",
        "given_name" => "World ID",
        "family_name" => "User",
        "https://id.worldcoin.org/v1" => { "verification_level" => "orb" }
      )
    end

    subject { strategy.info }

    it "includes name" do
      expect(subject[:name]).to eq("World ID User")
    end

    it "includes email" do
      expect(subject[:email]).to eq("0x2ae86d@id.worldcoin.org")
    end

    it "includes verification_level" do
      expect(subject[:verification_level]).to eq("orb")
    end

    it "includes orb_verified flag" do
      expect(subject[:orb_verified]).to be true
    end
  end
end
