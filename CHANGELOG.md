# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - Unreleased

### Changed
- **BREAKING:** requires Symfony `^7.4` (Symfony 6.4 is no longer supported). Consumers still on
  Symfony 6.4 must stay on `iseazy/security: ^2.0` (maintained in the `2.x` branch).
- Symfony dependencies use `^7.4` constraints instead of exact pinned versions.
- `symfony/http-kernel` and `symfony/security-core` are now declared explicitly (they were used
  but only pulled in transitively).
- `IseazySecurityExtension` extends `Symfony\Component\DependencyInjection\Extension\Extension`
  (the HttpKernel `Extension` is internal since Symfony 7.1).
- `CapabilityVoter::voteOnAttribute()` accepts the optional `?Vote $vote` argument introduced in
  Symfony 7.3 (forward compatible with Symfony 8).
- Dev: `squizlabs/php_codesniffer` constraint relaxed to `^4.0` (4.0.1 is blocked by a security advisory).

### Fixed
- `GlobalAuthorizationListener` validates `platformId` / `platformUid` with `Uuid::isValid()` (canonical
  RFC 4122 format). `Uuid::fromString()` accepted any 16-character string as a binary UUID, so values
  like `not-a-valid-uuid` were not rejected with `400 invalid_uuid`.
- Docs and config info now state the real header sent by `HttpCapabilityProvider`: `X-API-Key`
  (changed in 2.0.0 but still documented as `X-Service-API-Key`).
- Tests: fixed outdated `HttpCapabilityProvider` tests (expected header name, retry-after-timeout
  test using a bare `MockResponse`, mocking the final `Exception::getMessage()`).

## [2.0.1] - 2026-09-30

### Fixed
- `CapabilityFilter` now applies the documented "least restrictive capability wins" rule with the
  real context model: a PLATFORM capability (context: the platform id) absorbs the BUSINESS and
  HIERARCHY capabilities (context: business / hierarchy node ids) of the same action. Before, it
  compared contexts id by id, and a business id is never inside a platform id, so only GLOBAL (`*`)
  absorbed anything.
- The rule is now driven by `Scope` (restriction level and `Scope::covers()`): a new scope only has
  to be declared there to be absorbed by the scopes that cover it. BUSINESS and HIERARCHY still do
  not absorb each other.

### Changed
- `CapabilityFilterInterface::filterRestrictive()` documents its precondition: the collection must
  contain the capabilities of a single platform, because contexts are no longer compared.
- `composer.json` no longer declares `version`: the version comes from the git tag. A hardcoded
  version that does not match the tag makes Packagist skip the tag.

## [2.0.0] - 2026-05-29

### Added
- New namespace `Iseazy\Security\Authorization\` for capability-based authorization system
- Domain models: `Capability`, `Capabilities` collection, `Scope` value object
- Domain service interfaces (ports): `CapabilityProvider`, `JwtProvider`, `AuthorizationUser`
- Domain service: `CapabilityFilter` for filtering restrictive capabilities
- UI Voter: `CapabilityVoter` for Symfony Security integration
- Infrastructure adapters: `HttpCapabilityProvider` for fetching capabilities from remote HTTP API
- Infrastructure decorator: `CachedCapabilityProvider` for caching capability lookups
- Configuration tree `iseazy_security.authorization.*` with http and cache settings
- Domain exceptions: `InvalidCapabilityException`, `CapabilityProviderUnavailableException`

### Changed
- Minimum PHP version requirement raised to 8.3
- Extension now uses `Configuration` class for proper configuration tree processing
- JWT authenticator configuration now optional (only registered if `jwt_user_class` is configured)

### Fixed
- N/A

### Migration Guide from v1.x to v2.0

**Backward Compatibility:** v2.0 is fully backward-compatible with v1.x. The existing `Security\` namespace remains unchanged. The new `Authorization\` namespace is additive only.

**No Breaking Changes:** If you're using v1.x for JWT/API Key authentication, you can upgrade to v2.0 without any code changes. The authorization system is optional.

**To Use New Authorization Features:**
1. Upgrade to `iseazy/security:^2.0`
2. Implement a `CapabilityProvider` in your microservice (see README.md for examples)
3. Register the provider in your `services.yaml`
4. Use `CapabilityVoter` in your security checks (see README.md)

See README.md → Authorization section for detailed migration examples.

---

## [1.0.3] - 2026-05-28

### Changed
- Updated Symfony dependencies to 6.4.*
- Updated cache component version

---

## [1.0.2] - Earlier

### Added
- JWT authentication with Keycloak integration
- API Key authentication support
- User factory interfaces for custom user loading

---

[2.0.0]: https://github.com/iseazy/security/compare/v1.0.3...v2.0.0
[1.0.3]: https://github.com/iseazy/security/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/iseazy/security/releases/tag/v1.0.2
