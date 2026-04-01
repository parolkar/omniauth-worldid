# frozen_string_literal: true

require_relative "lib/omniauth_worldid/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth-worldid"
  spec.version       = OmniAuth::Worldid::VERSION
  spec.authors       = ["Abhishek Parolkar"]
  spec.email         = ["abhishek@parolkar.com"]
  spec.summary       = "OmniAuth strategy for World ID (Orb-based proof of humanity)"
  spec.description   = "An OmniAuth strategy that authenticates users via World ID's OIDC " \
                        "provider, enabling Ruby on Rails apps to verify that accounts belong " \
                        "to real humans verified by the Worldcoin Orb."
  spec.homepage      = "https://github.com/parolkar/omniauth-worldid"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.1"

  spec.files         = Dir["lib/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "omniauth-oauth2", "~> 1.8"

  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rack-test", "~> 2.0"
  spec.add_development_dependency "webmock", "~> 3.18"
  spec.add_development_dependency "rubocop", "~> 1.50"
end
