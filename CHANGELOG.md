# Changelog

## 0.1.0 (2026-04-01)

- Initial release
- OmniAuth OAuth2 strategy for World ID OIDC
- Authorization code flow against `https://id.worldcoin.org`
- Auth hash with `uid`, `verification_level`, `orb_verified` flag
- Configurable `min_verification_level` to enforce Orb-only auth
- Full `/userinfo` response in `extra[:raw_info]`
