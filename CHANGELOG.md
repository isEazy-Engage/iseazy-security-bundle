# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
