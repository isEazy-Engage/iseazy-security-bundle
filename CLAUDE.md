# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**iseazy/security** is a Symfony 6.4 bundle providing authentication and authorization for IsEazy microservices. Current version: 2.0.0

**Stack:** PHP 8.3+, Symfony 6.4, PHPUnit 12.2, PSR-12

**Two Main Features:**
1. **Authentication** (`Security\` namespace): JWT (Keycloak) + API Key authenticators
2. **Authorization** (`Authorization\` namespace): Capability-based access control with hexagonal architecture

## Development Commands

```bash
# Code style check (PSR-12)
composer cs

# Code style auto-fix
composer cbf

# Syntax check
php -l src/path/to/file.php

# Run tests (when PHPUnit is configured)
vendor/bin/phpunit
vendor/bin/phpunit tests/Authorization/Domain/Model/CapabilityTest.php  # Single test
```

## Architecture

### Security Module (Authentication)

**Location:** `src/Security/`

Simple authenticators for Symfony Security:
- `JwtAuthenticator`: Validates JWT from Keycloak, uses `JwtUserFactoryInterface` to create users
- `ApiKeyAuthenticator`: Validates API Keys, uses `ApiKeyUserFactoryInterface` to create users

**User Factory Pattern:** Consumer applications must implement `JwtUserFactoryInterface` or `ApiKeyUserFactoryInterface` to create their domain users from auth tokens.

### Authorization Module (v2.0+)

**Location:** `src/Authorization/`

**Hexagonal Architecture (Ports & Adapters):**

```
Authorization/
├── Domain/           # Core business logic, no framework dependencies
│   ├── Model/        # Capability, Capabilities, Scope (value objects)
│   ├── Service/      # Ports (interfaces): CapabilityProvider, AuthorizationUser
│   └── Exception/    # Domain exceptions
├── Infrastructure/   # Driven adapters (outbound)
│   ├── HttpCapabilityProvider.php    # Fetches capabilities from Platform API
│   └── CachedCapabilityProvider.php  # PSR-6 cache decorator
├── UI/               # Driving adapters (inbound)
│   └── Voter/        # CapabilityVoter (Symfony Security integration)
└── Application/      # Use cases (currently empty, may be used for CQRS)
```

**Key Concepts:**
- **Port:** Interface in `Domain/Service/` (e.g., `CapabilityProvider`)
- **Driving Adapter:** Entry point (UI layer) - `CapabilityVoter`
- **Driven Adapter:** Exit point (Infrastructure layer) - `HttpCapabilityProvider`, `CachedCapabilityProvider`

**Flow:**
1. Controller calls `$this->denyAccessUnlessGranted('campaign.edit', $subject)`
2. Symfony Security invokes `CapabilityVoter` (UI/Driving Adapter)
3. Voter calls `CapabilityProvider->capabilities()` (Port)
4. `HttpCapabilityProvider` fetches from Platform API (Infrastructure/Driven Adapter)
5. `CapabilityFilter` filters restrictive capabilities by scope
6. Voter grants/denies access

### Critical Architecture Decision: Service-to-Service Authentication

**IMPORTANT:** `HttpCapabilityProvider` uses **API Key authentication**, NOT JWT propagation.

**Why:**
- Background jobs, CLI commands, and workers have no user context
- Service-to-service auth should use service credentials, not user tokens
- Simplifies communication between microservices

**Implementation:**
- Header: `X-Service-API-Key: {key}`
- Endpoint: `GET /internal/api/v1/users/{userId}/capabilities?platformUid={platformId}`
- Config: `PLATFORM_SERVICE_API_KEY` environment variable

**Implications:**
- Platform microservice must provide `/internal/api/v1/users/{userId}/capabilities` endpoint
- Consumer microservices (Task, Supervisor) configure `PLATFORM_SERVICE_API_KEY`
- No `JwtProvider` needed (was removed in refactoring)

See `NOTES_ARCHITECTURE.md` for full architectural decision record.

## Code Conventions

**Follow PSR-12:** Run `composer cs` before committing.

**Authorization Module Conventions:**
- Use `declare(strict_types=1)` in all PHP files
- Prefer `readonly` classes where possible
- Use constructor property promotion
- Domain models are immutable value objects
- Ports (interfaces) go in `Domain/Service/`, not a separate `Contract/` folder
- Adapters implement or use ports, never both
- Named parameters in tests for clarity

**Namespace Rules:**
- `Security\`: Authentication (JWT, API Key)
- `Authorization\Domain\`: Core models, ports, domain services
- `Authorization\Infrastructure\`: Driven adapters (HTTP clients, cache, repositories)
- `Authorization\UI\`: Driving adapters (Voters, Controllers)
- `Authorization\Application\`: Application services (CQRS handlers) - currently unused

## Testing

**Test Structure:**
- `tests/` mirrors `src/` structure
- Use PHPUnit attributes: `#[Test]`, not docblock annotations
- Mock dependencies, test behavior
- Named parameters for test clarity: `new HttpCapabilityProvider(platformUrl: '...', serviceApiKey: '...')`

**Example Test Pattern:**
```php
#[Test]
public function testDescriptiveName(): void
{
    // ARRANGE
    $mock = $this->createMock(Dependency::class);
    $sut = new SystemUnderTest(dependency: $mock);
    
    // ACT
    $result = $sut->method();
    
    // ASSERT
    $this->assertSame($expected, $result);
}
```

## Configuration

**Bundle Configuration:** `src/DependencyInjection/Configuration.php`

**Auto-registered Services:**
- `config/authorization.yaml` registers `CapabilityFilter` and `CapabilityVoter`
- Consumer apps must register their own `CapabilityProvider` implementation

**Environment Variables:**
- Authentication: `IDAM_URI`, `IDAM_EXPECTED_ISSUER_URI`, `IDAM_AUDIENCE`, `API_KEY`
- Authorization: `PLATFORM_URL`, `PLATFORM_SERVICE_API_KEY`

## Two Usage Scenarios

**Producer (Platform):** Has database with capabilities. Implements `CapabilityProvider` using database queries. Provides HTTP API for consumers.

**Consumer (Task/Supervisor):** No capability database. Uses `HttpCapabilityProvider` to fetch from Platform. Optionally wraps with `CachedCapabilityProvider` decorator.

See `README.md` sections "Scenario 1" and "Scenario 2" for detailed setup.

## Common Patterns

**Fail-Closed Security:** All errors in `HttpCapabilityProvider` throw `CapabilityProviderUnavailableException`. Default behavior is deny on error (configurable via `fail_mode: closed`).

**Decorator Pattern:** `CachedCapabilityProvider` decorates any `CapabilityProvider` with PSR-6 caching. No changes to decorated provider needed.

**Port-Adapter:** Always depend on ports (interfaces in `Domain/Service/`), never on concrete adapters. Symfony DI resolves implementations.

## File Naming

- Domain models: `Capability.php`, `Scope.php` (singular, noun)
- Collections: `Capabilities.php` (plural)
- Services: `CapabilityFilter.php`, `CapabilityProvider.php` (noun)
- Adapters: `HttpCapabilityProvider.php`, `CachedCapabilityProvider.php` (adjective + noun)
- Voters: `CapabilityVoter.php`
- Tests: `{ClassName}Test.php`

## Version Notes

**v2.0.0 (current):**
- Added Authorization module with capability-based access control
- Hexagonal architecture for Authorization
- Backward compatible with v1.x (Security module unchanged)
- Service-to-service authentication uses API Key (architectural decision)

**v1.x:**
- JWT and API Key authentication only
- No authorization features
