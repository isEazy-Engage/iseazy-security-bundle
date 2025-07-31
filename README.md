# Iseazy Security Bundle

Este paquete proporciona autenticadores para Symfony que permiten validar JWT emitidos por Keycloak y autenticación por API Key.

---

## Instalación

1. Añade el paquete a tu proyecto Symfony con Composer:

```bash
composer require iseazy/security
```

2. Define el parámetro idam_uri en tu configuración para indicar la URL base de tu servidor de identidad::

```
# config/packages/iseazy_security.yaml
iseazy_security:
  idam_uri: http://localhost:8118
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

use Iseazy\Security\Security\JwtUserFactoryInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class MyUserFactory implements JwtUserFactoryInterface
{
    public function createUser(array $payload): UserInterface
    {
        // Tu lógica para crear o cargar el usuario desde el payload JWT
        return User::createFromPayload($payload);
    }
}
```

5. Registra tu fábrica de usuarios como un servicio:

```yaml
# config/services.yaml
ervices:
  App\Security\MyUserFactory: ~

  Iseazy\Security\Security\JwtAuthenticator:
    arguments:
      $idamUri: '%iseazy_security.idam_uri%'
      $userFactory: '@App\Security\MyUserFactory'
```# iseazy-security-bundle
