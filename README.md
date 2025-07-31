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

```phpnamespace App\Security;

use Iseazy\Security\Security\IseazyUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class MyUserFactory implements IseazyUserInterface
{
    public function createUser(array $payload): UserInterface
    {
        // Tu lógica para crear o cargar el usuario desde el payload JWT
        return User::createFromPayload($payload);
    }
}
```

