# omniauth-worldid

OmniAuth strategy for [World ID](https://world.org/world-id) — proof-of-humanity authentication for Ruby on Rails.

## Why

AI can now register accounts, pass CAPTCHAs, and impersonate humans online. World ID solves this at the identity layer: users verify their humanness once at a physical [Orb](https://www.toolsforhumanity.com/orb) (iris biometrics by Tools for Humanity), then authenticate anywhere via standard OIDC. This gem brings that to Rails.

**~100 lines of Ruby.** One strategy class, one version file, one require. No magic.

## How it works

1. User clicks "Sign in with World ID" in your Rails app
2. Redirected to `https://id.worldcoin.org/authorize` (standard OIDC Authorization Code flow)
3. User authenticates via World App on their phone
4. Callback returns an auth hash with `uid`, `verification_level` (`"orb"` or `"device"`), and profile info
5. Your app knows this account belongs to a verified human

## Install

```ruby
# Gemfile
gem "omniauth-worldid"
```

## Usage

Register your app at the [World ID Developer Portal](https://developer.worldcoin.org) to get a `client_id` and `client_secret`.

```ruby
# config/initializers/omniauth.rb
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :worldid,
    ENV["WORLDID_CLIENT_ID"],
    ENV["WORLDID_CLIENT_SECRET"],
    scope: "openid profile email"
end
```

### Auth hash

```ruby
request.env["omniauth.auth"]
# =>
# {
#   uid: "0x2ae86d6d747702b3b...",
#   info: {
#     name: "World ID User",
#     email: "0x2ae86d@id.worldcoin.org",
#     verification_level: "orb",   # "orb" or "device"
#     orb_verified: true
#   },
#   extra: { raw_info: { ... } }
# }
```

### Enforce Orb-only verification

```ruby
provider :worldid,
  ENV["WORLDID_CLIENT_ID"],
  ENV["WORLDID_CLIENT_SECRET"],
  min_verification_level: "orb"  # Rejects device-only verifications
```

### With Devise

```ruby
# config/initializers/devise.rb
config.omniauth :worldid,
  ENV["WORLDID_CLIENT_ID"],
  ENV["WORLDID_CLIENT_SECRET"],
  scope: "openid profile email"
```

## Verification levels

| Level | Meaning | Strength |
|-------|---------|----------|
| `orb` | Verified at a physical Orb via iris biometrics | Strong — unique human confirmed |
| `device` | Verified via World App on a trusted device | Moderate — device-bound, not biometric |

## API Reference

The strategy hits these [World ID OIDC endpoints](https://docs.world.org/world-id/reference/sign-in):

- `GET /authorize` — begin sign-in
- `POST /token` — exchange code for tokens (Basic Auth)
- `POST /userinfo` — fetch user profile + verification level
- `GET /jwks` — token verification keys

## License

MIT — Abhishek Parolkar
