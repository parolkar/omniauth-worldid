# Changelog

## 0.2.0 (2026-07-31)

### Added
- **`OmniAuth::Strategies::WorldidV4`** — World ID 4.0 proof-of-human flow.
  - `POST /auth/worldid_v4` returns a signed RP context `{sig, nonce, created_at, expires_at}`
    the client passes to IDKit/World App to generate a ZK proof.
  - `POST /auth/worldid_v4/callback` verifies the posted proof server-side via
    `POST https://developer.world.org/api/v4/verify/{rp_id}` and exposes the human
    `nullifier` as the OmniAuth `uid`.
- **`OmniAuth::Worldid::RpSigner`** — pure-Ruby (via `eth` gem) RP signature implementation
  (Keccak-256 + EIP-191 + secp256k1/RFC 6979). Proven byte-for-byte against every
  official World ID test vector in `signatures.md` (hash_to_field, signature_message,
  sign_request with and without action).
- **`OmniAuth::Worldid::ProofVerifier`** — forwards the IDKit result payload as-is to
  the v4 verification service; normalizes success/error into a Result struct.

### Fixed
- **`callback_phase` was declared `private`** in the legacy OIDC strategy. OmniAuth
  invokes it as a public method from `Strategy#callback_call` (omniauth 2.x), so any
  real callback raised `NoMethodError` and `min_verification_level: "orb"` enforcement
  never worked. It is public now and exercised by strategy tests.

### Notes
- `WorldidV4#request_phase` is a JSON API endpoint; OmniAuth 2.x authenticity-token
  protection (designed for HTML form sign-ins) does not apply. Host apps that prefer
  to sign the RP context in their own controller can use `OmniAuth::Worldid::RpSigner`
  directly.
- New runtime dependency: `eth ~> 0.5` (pure keccak + secp256k1 signing).
- Tests: 30 examples, 0 failures (was 13 examples, 0 failures).

## 0.1.0 (2026-04-01)

- Initial release
- OmniAuth OAuth2 strategy for World ID OIDC
- Authorization code flow against `https://id.worldcoin.org`
- Auth hash with `uid`, `verification_level`, `orb_verified` flag
- Configurable `min_verification_level` to enforce Orb-only auth
- Full `/userinfo` response in `extra[:raw_info]`
