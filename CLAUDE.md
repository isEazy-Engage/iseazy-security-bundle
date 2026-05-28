# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Symfony 6.4 bundle (`iseazy/security`) that provides authentication mechanisms for microservices. It supports:
- JWT authentication with Keycloak (using JWKS with caching)
- API Key authentication

## Development Commands

### Testing
```bash
# Run all tests
vendor/bin/phpunit

# Run specific test file
vendor/bin/phpunit tests/Security/JwtAuthenticatorTest.php
```

### Code Quality
```bash
# Check coding standards (PSR-12)
composer cs

# Auto-fix coding standards
composer cbf
```

### Dependencies
```bash
# Install dependencies
composer install

# Update dependencies
composer update
```

## Architecture

### Bundle Structure

- **IseazySecurityBundle**: Main bundle entry point
- **IseazySecurityExtension**: Handles dependency injection and configuration
  - Registers authenticators based on config
  - Validates user factory classes implement required interfaces
  - Loads services from `config/services.yaml`

### Authentication Flow

The bundle provides two authenticators that implement Symfony's `AbstractAuthenticator`:

1. **JwtAuthenticator** (`src/Security/JwtAuthenticator.php`)
   - Validates Bearer tokens from Authorization header
   - Fetches JWKS from Keycloak and caches for 5 minutes
   - Validates issuer and expiration
   - Uses consumer-provided `JwtUserFactoryInterface::createFromJwtPayload()` to create user objects

2. **ApiKeyAuthenticator** (`src/Security/ApiKeyAuthenticator.php`)
   - Validates X-API-Key header
   - Extracts optional `platformId`/`platformUid` from query parameters
   - Uses consumer-provided `ApiKeyUserFactoryInterface::createFromApiKey()` to create user objects

### User Factory Pattern

Consumers must implement factory interfaces to create user objects:

- **JwtUserFactoryInterface**: Must implement `createFromJwtPayload(array $payload): UserInterface` and `getPlatformId(): string`
- **ApiKeyUserFactoryInterface**: Must implement `createFromApiKey(string $apiKey, ?string $platformId): UserInterface` and `getPlatformId(): ?string`

These are configured in consuming application's `config/packages/iseazy_security.yaml`:
```yaml
iseazy_security:
    jwt_user_class: App\Security\JwtUserFactory
    api_key_user_class: App\Security\ApiKeyUserFactory  # Optional
```

### Global Authorization Listener

`GlobalAuthorizationListener` runs on every kernel request (priority -100) and:
- Only processes requests on the `api` firewall
- Validates `platformId`/`platformUid` query params are valid UUIDs if present
- Ensures user is authenticated
- Contains commented-out platform access checks (currently disabled)

### Configuration Requirements

Required environment variables:
- `IDAM_URI`: Keycloak server URL
- `IDAM_EXPECTED_ISSUER_URI`: Expected JWT issuer base URL
- `IDAM_AUDIENCE`: JWT audience (defaults to "IsEazy" if not set)
- `API_KEY`: API key for API Key authentication (if using ApiKeyAuthenticator)

Bundle configuration parameters (in `config/packages/iseazy_security.yaml`):
- `jwt_user_class`: Factory class for creating JWT users (required)
- `api_key_user_class`: Factory class for creating API Key users (optional)
- `enable_global_listener`: Enable/disable GlobalAuthorizationListener (default: true)

### Caching

JwtAuthenticator uses Symfony Cache component to cache JWKS responses:
- Cache key: `jwks_cache`
- TTL: 300 seconds (5 minutes)
- Prevents excessive calls to Keycloak's JWKS endpoint

### Observability

All components log to the `security` Monolog channel with structured data:

**JwtAuthenticator logs:**
- Authentication success/failure with user context
- Token validation errors (issuer mismatch, expiration)
- JWKS fetch success/failure with error details

**ApiKeyAuthenticator logs:**
- Authentication success/failure with platform_id
- Missing or invalid API key attempts
- IP and request context

**GlobalAuthorizationListener logs:**
- Unauthenticated access attempts
- Invalid UUID format in query parameters
- Authorization check results

**Log context includes:** user_id, platform_id, username, uri, method, ip, error details, timestamps

**ELK integration:** Logs are JSON-structured and ready for Elasticsearch ingestion via Monolog handlers

## Testing Patterns

Tests use PHPUnit and include:
- Mock JWT tokens signed with test RSA keys (`tests/config/jwt/`)
- Mock JWKS responses for validation
- Dummy user factory implementations for isolated testing
- Tests cover: supports(), authenticate(), and error cases

## Important Implementation Details

1. **User Factory Validation**: The DI extension validates at container build time that configured user factory classes implement the required interfaces
2. **Static Factory Methods**: User factories use static factory methods (`createFromJwtPayload`, `createFromApiKey`) to create user instances
3. **Firewall Context**: The GlobalAuthorizationListener specifically looks for `security.firewall.map.context.api` firewall context
4. **Platform ID Extraction**: For API Key auth, `platformId` can come from query param as either `platformId` or `platformUid`
