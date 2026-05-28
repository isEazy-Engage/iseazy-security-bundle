# Iseazy Security Bundle

Este paquete proporciona autenticadores para Symfony que permiten validar JWT emitidos por Keycloak y autenticación por API Key.

---

## Instalación

1. Añade el paquete a tu proyecto Symfony con Composer:

```bash
composer require iseazy/security
```

2. Define los parámetros necesarios en tu archivo de configuración:
   Si usas jwt con keycloak, asegúrate de definir las variables de entorno necesarias en tu archivo `.env`:

- IDAM_URI es la URL de tu servidor Keycloak.
- IDAM_EXPECTER_ISSUER_URI es la URL de tu aplicación que espera el emisor del JWT.
- IDAM_AUDIENCE es el público esperado del JWT. Si no esta definido, se usará el valor por defecto `IsEazy`.
```
# .env
IDAM_URI=https://keycloak.example.com
IDAM_EXPECTER_ISSUER_URI=http://localhost:8118
IDAM_AUDIENCE=IsEazy
```

Si usas autenticación por API Key, define la clave en tu archivo `.env`:

```
# .env
API_KEY=your_api_key_here
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

5. Le indicamos a Symfony que use estas clases como proveedores de usuarios en tu configuración de seguridad:

```yaml
# config/packages/iseazy_security.yaml
iseazy_security:
    jwt_user_class: TaskBundle\Context\User\Domain\Entity\User
    api_key_user_class: TaskBundle\Context\User\Domain\Entity\ApiKeyUser
    enable_global_listener: true  # Opcional: habilita/deshabilita el GlobalAuthorizationListener (por defecto: true)
```

## Configuración Avanzada

### GlobalAuthorizationListener

El bundle incluye un `GlobalAuthorizationListener` que valida:
- UUIDs válidos en parámetros `platformId`/`platformUid`
- Que el usuario esté autenticado en el firewall `api`

Si necesitas deshabilitarlo (por ejemplo, para endpoints públicos o para usar `security: false`), puedes hacerlo en la configuración:

```yaml
# config/packages/iseazy_security.yaml
iseazy_security:
    jwt_user_class: TaskBundle\Context\User\Domain\Entity\User
    enable_global_listener: false  # Deshabilita el listener
```

### Observabilidad y Logging

El bundle escribe logs estructurados utilizando el canal **`security`** de Monolog (si está disponible), compatibles con ELK Stack.

**✅ Funciona sin configuración:** Si no configuras Monolog, los logs irán al logger por defecto de Symfony.

**✅ Canal automático:** El tag `monolog.logger` con `channel: 'security'` crea el canal automáticamente si Monolog está instalado.

#### Eventos registrados:

- ✅ Autenticación JWT exitosa/fallida
- ✅ Autenticación API Key exitosa/fallida
- ✅ Errores de validación de tokens
- ✅ Intentos de acceso no autenticados
- ✅ UUIDs inválidos en parámetros
- ✅ Errores al obtener JWKS de Keycloak

#### Contexto incluido en logs:
Todos los logs incluyen contexto rico para facilitar búsquedas y análisis:
- `user_id`, `platform_id`, `username`
- `uri`, `method`, `ip`
- `error`, `exception_class`
- Timestamps, issuer, expiration dates

#### Configuración para ELK (Opcional)

Hay 3 opciones de configuración según tus necesidades:

**Opción 1: Sin configuración (logs por defecto)**
No necesitas configurar nada. Los logs irán a `var/log/dev.log` o `var/log/prod.log` según el entorno.

**Opción 2: Separar logs de seguridad en archivo propio**
```yaml
# config/packages/monolog.yaml
monolog:
    channels: ['security']
    handlers:
        security:
            type: stream
            path: "%kernel.logs_dir%/security.log"
            level: info
            channels: ['security']
            formatter: 'monolog.formatter.json'  # JSON para ELK
```

**Opción 3: Enviar directamente a Elasticsearch**
```yaml
# config/packages/monolog.yaml
monolog:
    channels: ['security']
    handlers:
        elasticsearch:
            type: elasticsearch
            index: security-logs
            level: info
            channels: ['security']
```

#### Ejemplo de log estructurado:

```json
{
  "message": "JWT authentication successful",
  "context": {
    "user_id": "f:realm:c34fc026-c263-4a9e-ad0d-98c6d67bf769",
    "platform_id": "3b594402-bda5-4f77-96d4-75f1a964bcbe",
    "username": "john.doe@example.com",
    "uri": "/api/campaigns",
    "method": "GET",
    "ip": "192.168.1.100"
  },
  "level": "INFO",
  "channel": "security",
  "datetime": "2025-05-28T10:30:45+00:00"
}
```
