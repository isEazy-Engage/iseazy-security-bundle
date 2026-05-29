# Notas de Arquitectura - Bundle iseazy/security

## Decisiones de Arquitectura Implementadas

### 1. Autenticación Service-to-Service para HttpCapabilityProvider

**Fecha Decisión:** 2026-05-29  
**Estado:** ✅ IMPLEMENTADO

**Contexto:**
Inicialmente `HttpCapabilityProvider` usaba `JwtProvider` para obtener el JWT del usuario y autenticarse contra Platform API. Esto presentaba limitaciones para comunicación service-to-service:

**Problemas del Enfoque JWT:**
- Background jobs no tienen usuario autenticado
- Service-to-service debería usar credenciales de servicio, no de usuario
- El JWT del usuario puede no tener permisos para endpoints internos
- Requiere propagar el JWT del usuario a través de workers/queues

**Solución Implementada: API Key de Servicio**

Se eligió el enfoque de API Key para autenticación service-to-service por su simplicidad y adecuación al caso de uso.

**Implementación:**
- `HttpCapabilityProvider` ahora usa `$serviceApiKey` en lugar de `JwtProvider`
- Header de autenticación: `X-Service-API-Key: {key}`
- Endpoint interno: `GET /internal/api/v1/users/{userId}/capabilities?platformUid={platformId}`
- `JwtProvider` interface eliminada (ya no es necesaria en el bundle)

**Ventajas:**
- Simple de configurar y gestionar
- No requiere contexto de usuario
- Funciona en background jobs, CLI commands, workers
- Comunicación clara de intención (service-to-service vs user authentication)

**Desventajas Aceptadas:**
- Requiere gestión segura de API Keys (rotación, almacenamiento)
- No tiene expiración automática (como OAuth2 tokens)

**Impacto en Tareas Futuras:**
- **TASK-015 (Platform):** Crear endpoint `/internal/api/v1/users/{userId}/capabilities` que valide `X-Service-API-Key` header
- **TASK-018+ (Task/Supervisor):** Configurar variable de entorno `PLATFORM_SERVICE_API_KEY`

**Alternativas Consideradas (No Implementadas):**
1. **OAuth2 Client Credentials:** Más complejo, overhead innecesario para comunicación interna
2. **Dual Authentication (JWT + API Key):** Mayor complejidad de código, no justificada para el caso de uso

---

## Referencias

- TASK-007: Implementación de HttpCapabilityProvider
- TASK-009: Refactorización a API Key (service-to-service authentication)
- ADR-001: Service-to-Service Authentication Strategy (API Key)
