# Iseazy Security Bundle

Este paquete proporciona autenticadores para Symfony que permiten validar JWT emitidos por Keycloak y autenticación por API Key.

---

## Instalación

1. Añade el paquete a tu proyecto Symfony con Composer:

```bash
composer require iseazy/security
```

2. Define las variables de entorno necesarias en tu archivo `.env` según los módulos que actives:

**JWT (Keycloak):**
- `IDAM_URI` — URL base del servidor Keycloak
- `IDAM_EXPECTED_ISSUER_URI` — URL del emisor esperado del JWT
- `IDAM_AUDIENCE` — Audience del JWT (por defecto: `IsEazy`)

```
# .env
IDAM_URI=https://keycloak.example.com
IDAM_EXPECTED_ISSUER_URI=http://localhost:8118
IDAM_AUDIENCE=IsEazy
```

**API Key:**
```
# .env
API_KEY=your_api_key_here
```

**Authorization (módulo de capabilities):**
```
# .env
PLATFORM_URL=https://platform.example.com
PLATFORM_SERVICE_API_KEY=your-service-api-key-here
```

3. Configura el firewall en tu archivo de configuración de seguridad:

```yaml
# config/packages/security.yaml
security:
  firewalls:
    api:
      pattern: ^/api
      stateless: true
      custom_authenticators:
        - Iseazy\Security\Security\JwtAuthenticator
        - Iseazy\Security\Security\ApiKeyAuthenticator
      entry_point: Iseazy\Security\Security\JwtAuthenticator

  access_control:
    - { path: ^/api, roles: ROLE_USER }
```
4. Configura el proveedor de usuarios para usar el servicio de usuario de Iseazy:

- Para JWT, implementa la interfaz `JwtUserFactoryInterface` y crea un servicio que devuelva el usuario basado en el
  payload del JWT.

```php

use Iseazy\Security\Security\IseazyUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserFactory implements JwtUserFactoryInterface
{
    public function createUser(array $payload): UserInterface
    {
        // Tu lógica para crear o cargar el usuario desde el payload JWT
        return User::createFromPayload($payload);
    }
}
```

- Para API Key, implementa la interfaz `ApiKeyUserFactoryInterface` y crea un servicio que devuelva el usuario basado en
  la clave API.

```php
use Iseazy\Security\Security\ApiKeyUserFactoryInterface;
use Symfony\Component\Security\Core\User\UserInterface;
class ApiKeyUserFactory implements ApiKeyUserFactoryInterface
{
    public function createUser(string $apiKey): UserInterface
    {
        // Tu lógica para crear o cargar el usuario desde la clave API
        return User::createFromApiKey($apiKey);
    }
}
```

5. Crea el archivo de configuración del bundle y activa los módulos que necesites:

```yaml
# config/packages/iseazy_security.yaml
iseazy_security:
    jwt:
        enabled: true
        user_class: App\Context\Security\Domain\Entity\User
    api_key:
        enabled: true
        user_class: App\Context\Security\Domain\Entity\ApiKeyUser
    authorization:
        enabled: false   # Activar solo si usas el módulo de capabilities (ver sección Authorization)
        cache:
            ttl: 900
        http:
            timeout: 3
            fail_mode: closed
```

Cada módulo es independiente: puedes activar solo JWT, solo API Key, solo Authorization, o cualquier combinación.

---

## Authorization (v2.0+)

Starting from version 2.0, this bundle includes a capability-based authorization system. This allows microservices to implement fine-grained access control based on user capabilities and scopes.

### Key Concepts

- **Capability**: A permission to perform an action (e.g., `campaign.edit`, `task.delete`)
- **Scope**: A domain-specific restriction on a capability (e.g., user can only edit campaigns in their organization)
- **CapabilityProvider**: Service that fetches user capabilities from a source (database, HTTP API, cache)
- **CapabilityVoter**: Symfony Security Voter that integrates capabilities into the authorization system
- **CapabilityFilter**: Domain service for filtering restrictive (scoped) capabilities

### Architecture Overview

The authorization system follows **Hexagonal Architecture (Ports and Adapters)**:

- **Domain Layer**: `Capability`, `Capabilities`, `Scope` (models), `CapabilityProvider` interface (port), `CapabilityFilter` (service)
- **Infrastructure Layer**: `HttpCapabilityProvider` (adapter for remote API), `CachedCapabilityProvider` (decorator for caching)
- **UI Layer**: `CapabilityVoter` (Symfony Security integration)

### Installation

```bash
composer require iseazy/security:^2.0
```

### Configuration

Referencia completa de opciones disponibles:

```yaml
# config/packages/iseazy_security.yaml
iseazy_security:
    jwt:
        enabled: false                          # Activar autenticador JWT
        user_class: ~                           # FQCN que implementa JwtUserFactoryInterface
    api_key:
        enabled: false                          # Activar autenticador API Key
        user_class: ~                           # FQCN que implementa ApiKeyUserFactoryInterface
    authorization:
        enabled: false                          # Activar módulo de capabilities
        http:
            timeout: 3                          # Timeout HTTP en segundos (1-30)
            fail_mode: closed                   # 'closed' (denegar) o 'open' (permitir) si Platform no responde
        cache:
            ttl: 900                            # TTL de caché en segundos (0 = sin caché)
```

Para ver la referencia generada por Symfony:

```bash
bin/console config:dump-reference iseazy_security
```

### Usage Scenarios

The bundle supports two main usage scenarios:

#### Scenario 1: Producer (Platform Microservice)

Platform microservice is the **source of truth** for user capabilities. It stores capabilities in its database and provides them to other microservices.

**Step 1:** Implement `CapabilityProvider` using your database:

```php
<?php

declare(strict_types=1);

namespace App\Infrastructure\Authorization;

use Iseazy\Security\Authorization\Domain\Model\Capabilities;
use Iseazy\Security\Authorization\Domain\Service\CapabilityProvider;
use Iseazy\Security\Authorization\Domain\Service\AuthorizationUser;
use Doctrine\ORM\EntityManagerInterface;

final class DatabaseCapabilityProvider implements CapabilityProvider
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager
    ) {
    }

    public function capabilitiesFor(AuthorizationUser $user): Capabilities
    {
        // Fetch capabilities from database
        $capabilities = $this->entityManager
            ->getRepository(UserCapability::class)
            ->findByUserId($user->id());

        return Capabilities::fromArray(
            array_map(
                fn(UserCapability $cap) => [
                    'name' => $cap->name(),
                    'scope' => $cap->scope()?->value(),
                ],
                $capabilities
            )
        );
    }
}
```

**Step 2:** Register the provider:

```yaml
# config/services.yaml
services:
    # Register your database provider as the CapabilityProvider port
    Iseazy\Security\Authorization\Domain\Service\CapabilityProvider:
        class: App\Infrastructure\Authorization\DatabaseCapabilityProvider
```

**Step 3:** Use `CapabilityVoter` in your controllers:

```php
#[Route('/api/campaigns/{id}', methods: ['PUT'])]
public function update(string $id): Response
{
    $this->denyAccessUnlessGranted('campaign.edit', $id);
    
    // Your logic here
}
```

---

#### Scenario 2: Consumer (Task/Supervisor Microservices)

Task and Supervisor microservices **fetch capabilities from Platform** via HTTP API.

> **Important:** `HttpCapabilityProvider` uses **service-to-service authentication** with an API Key, not user JWT. This allows it to work in background jobs, CLI commands, and workers where no user context exists.

**Step 1:** Register `HttpCapabilityProvider`:

```yaml
# config/services.yaml
services:
    # Base HTTP provider with service-to-service authentication
    Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider:
        arguments:
            $platformUrl: '%env(PLATFORM_URL)%'
            $serviceApiKey: '%env(PLATFORM_SERVICE_API_KEY)%'
            $httpClient: '@http_client'
            $logger: '@logger'
            $timeoutSeconds: 3
            $failClosed: true

    # Register as the CapabilityProvider port
    Iseazy\Security\Authorization\Domain\Service\CapabilityProvider:
        alias: Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider
```

**Step 2 (Optional):** Add caching with `CachedCapabilityProvider`:

```yaml
# config/services.yaml
services:
    # Base HTTP provider
    Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider:
        arguments:
            $platformUrl: '%env(PLATFORM_URL)%'
            $serviceApiKey: '%env(PLATFORM_SERVICE_API_KEY)%'
            $httpClient: '@http_client'
            $logger: '@logger'
            $timeoutSeconds: 3
            $failClosed: true

    # Cached decorator
    Iseazy\Security\Authorization\Infrastructure\CachedCapabilityProvider:
        decorates: Iseazy\Security\Authorization\Infrastructure\HttpCapabilityProvider
        arguments:
            $inner: '@.inner'
            $cache: '@cache.app'
            $ttl: '%iseazy_security.authorization.cache.ttl%'

    # Register cached provider as the port
    Iseazy\Security\Authorization\Domain\Service\CapabilityProvider:
        alias: Iseazy\Security\Authorization\Infrastructure\CachedCapabilityProvider
```

**Step 3:** Define Platform API URL and Service API Key:

```bash
# .env
PLATFORM_URL=https://platform.example.com
PLATFORM_SERVICE_API_KEY=your-service-api-key-here
```

**Step 4:** Use `CapabilityVoter` in your controllers:

```php
#[Route('/api/tasks/{id}', methods: ['DELETE'])]
public function delete(string $id): Response
{
    $this->denyAccessUnlessGranted('task.delete', $id);
    
    // Your logic here
}
```

---

### How CapabilityVoter Works

The `CapabilityVoter` integrates with Symfony Security's authorization system:

1. When you call `$this->denyAccessUnlessGranted('campaign.edit', $subject)`:
   - Symfony calls `CapabilityVoter::vote()`
   - Voter extracts the user from the security token (must implement `AuthorizationUser`)
   - Voter calls `CapabilityProvider::capabilitiesFor($user)` to fetch capabilities
   - Voter checks if user has the requested capability
   - If capability has a scope, voter calls `CapabilityFilter::filterRestrictive()` to apply scope restrictions

2. **Unrestricted capabilities** (no scope):
   - `campaign.edit` with no scope → User can edit ANY campaign
   - Voter grants access

3. **Restrictive capabilities** (with scope):
   - `campaign.edit` with scope `organization:123` → User can only edit campaigns in organization 123
   - Voter uses `CapabilityFilter` to check if the subject (campaign) matches the scope
   - Voter grants access only if scope matches

### User Implementation

Your User class must implement `AuthorizationUser`:

```php
<?php

declare(strict_types=1);

namespace App\Domain\User;

use Iseazy\Security\Authorization\Domain\Service\AuthorizationUser;
use Symfony\Component\Security\Core\User\UserInterface;

final class User implements UserInterface, AuthorizationUser
{
    public function __construct(
        private readonly string $id,
        private readonly string $email,
        private readonly array $roles
    ) {
    }

    public function id(): string
    {
        return $this->id;
    }

    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials(): void
    {
        // Nothing to erase
    }
}
```

### Advanced: Custom Scope Filtering

By default, `CapabilityFilter` performs simple string matching. For custom scope filtering logic, extend `CapabilityFilter`:

```php
<?php

declare(strict_types=1);

namespace App\Domain\Authorization;

use Iseazy\Security\Authorization\Domain\Service\CapabilityFilter as BaseCapabilityFilter;
use Iseazy\Security\Authorization\Domain\Model\Capabilities;

final class CustomCapabilityFilter extends BaseCapabilityFilter
{
    public function filterRestrictive(Capabilities $capabilities, string $capabilityName, mixed $subject): Capabilities
    {
        // Your custom filtering logic
        // Example: Parse scope as JSON, extract filters, apply to subject
        
        return parent::filterRestrictive($capabilities, $capabilityName, $subject);
    }
}
```

Then register your custom filter:

```yaml
services:
    Iseazy\Security\Authorization\Domain\Service\CapabilityFilter:
        class: App\Domain\Authorization\CustomCapabilityFilter
```

### Error Handling

- **HTTP timeout**: Configurable via `iseazy_security.authorization.http.timeout`
- **Platform unavailable**: Behavior controlled by `fail_mode`:
  - `closed` (default): Deny access when Platform is unreachable (fail-safe)
  - `open`: Allow access when Platform is unreachable (fail-open, use with caution)
- **Cache miss**: `CachedCapabilityProvider` transparently fetches from HTTP if cache miss

### Performance Recommendations

1. **Use caching in consumer microservices**: Reduces HTTP calls to Platform
2. **Tune cache TTL**: Balance between freshness and performance
3. **Monitor HTTP timeouts**: Adjust timeout based on network latency
4. **Use fail-closed mode in production**: Safer default (deny on error)

### Debugging

Enable debug mode to see voter decisions:

```yaml
# config/packages/dev/security.yaml
security:
    enable_authenticator_manager: true
    # Add this for voter debugging
    access_decision_manager:
        strategy: unanimous
        allow_if_all_abstain: false
        allow_if_equal_granted_denied: true
```

Check logs for voter decisions:

```bash
tail -f var/log/dev.log | grep CapabilityVoter
```

### Migration from v1.x to v2.0

**Cambio de configuración requerido.** El formato del bloque `iseazy_security` cambió en v2.0.

**Antes (v1.x):**
```yaml
iseazy_security:
    jwt_user_class: App\Security\User
    api_key_user_class: App\Security\ApiKeyUser
```

**Después (v2.0):**
```yaml
iseazy_security:
    jwt:
        enabled: true
        user_class: App\Security\User
    api_key:
        enabled: true
        user_class: App\Security\ApiKeyUser
```

**Para adoptar el módulo de Authorization:**

1. Actualiza a `iseazy/security:^2.0`
2. Elige tu escenario (Productor o Consumidor, ver secciones anteriores)
3. Implementa y registra tu `CapabilityProvider`
4. Haz que tu clase User implemente `AuthorizationUser`
5. Activa el módulo: `authorization.enabled: true`
6. Usa `$this->denyAccessUnlessGranted('capability.name', $subject)` en los controladores

**Antes (v1.x) — check manual:**
```php
if (!$this->userHasCapability($user, 'campaign.edit')) {
    throw new AccessDeniedException();
}
```

**Después (v2.0) — integración con Symfony Security:**
```php
$this->denyAccessUnlessGranted('campaign.edit', $campaignId);
```

### Troubleshooting

**Problem:** `CapabilityVoter` not found
- **Solution:** Ensure `config/authorization.yaml` is loaded. Check `bin/console debug:container CapabilityVoter`

**Problem:** HTTP timeout errors
- **Solution:** Increase `iseazy_security.authorization.http.timeout` or check Platform API availability

**Problem:** User denied access despite having capability
- **Solution:** Check if capability has a scope. Enable voter debugging to see decision logs.

**Problem:** Capabilities not cached
- **Solution:** Ensure `CachedCapabilityProvider` is registered and decorates `HttpCapabilityProvider`

---

## Contributing

Contributions are welcome. Please follow PSR-12 coding standards and include tests for new features.

## License

This bundle is proprietary software owned by IsEazy.
