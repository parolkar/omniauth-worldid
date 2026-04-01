# frozen_string_literal: true

require "bundler/setup"
require "omniauth-worldid"
require "rack/test"
require "webmock/rspec"

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
