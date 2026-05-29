# Notas de Arquitectura - Bundle iseazy/security

## Decisiones Pendientes de Revisión

### 1. Autenticación Service-to-Service para HttpCapabilityProvider

**Fecha:** 2026-05-29  
**Contexto:** Actualmente `HttpCapabilityProvider` usa `JwtProvider` para obtener el JWT del usuario y autenticarse contra Platform API.

**Problema Identificado:**
- Para comunicación interna entre microservicios (Task → Platform, Supervisor → Platform), usar el JWT del usuario tiene limitaciones:
  - Background jobs no tienen usuario autenticado
  - Service-to-service debería usar credenciales de servicio, no de usuario
  - El JWT del usuario puede no tener permisos para endpoints internos
  - Requiere propagar el JWT del usuario a través de workers/queues

**Alternativas a Considerar:**

1. **API Key de Servicio** (Service-to-Service)
   - Cada microservicio tiene una API Key para autenticarse
   - Header: `X-Service-API-Key: {key}`
   - Platform valida que el servicio tiene permisos
   - Pros: Simple, no requiere usuario
   - Contras: Gestión de API Keys

2. **OAuth2 Client Credentials**
   - Service token con OAuth2 client credentials flow
   - Header: `Authorization: Bearer {service_token}`
   - Tokens con tiempo de vida corto
   - Pros: Estándar, tokens temporales
   - Contras: Más complejo

3. **Dual Authentication** (Híbrido)
   - Soportar ambos: JWT usuario + API Key servicio
   - Fallback: si no hay JWT, usar service credentials
   - Pros: Flexible, soporta ambos casos
   - Contras: Más código, más complejidad

**Decisión Pendiente:**
- Evaluar si Platform API puede/debe soportar autenticación de servicio
- Decidir mecanismo: API Key vs Client Credentials vs Dual
- Implementar abstracción: `AuthProvider` que encapsule ambos métodos

**Impacto:**
- Afecta a: `HttpCapabilityProvider`, `JwtProvider`
- Posible nueva interface: `ServiceAuthProvider` o `AuthProvider`
- Cambio en Platform API (endpoint capabilities)

**Acción Recomendada:**
- Revisar al final del desarrollo
- Considerar en TASK-008 (configuración del bundle)
- Documentar en ADR (Architecture Decision Record)

---

## Referencias

- TASK-007: Implementación de HttpCapabilityProvider
- ADR-XXX: (pendiente) Service-to-Service Authentication Strategy
