# GitHub Packages Configuration

Este documento explica cómo usar el paquete `iseazy/security` desde GitHub Packages (repositorio privado).

## Para Desarrolladores (Configuración Local)

### Opción 1: Configuración Global (Recomendado)

Ejecutar **una sola vez** en tu máquina:

```bash
composer config --global --auth github-oauth.github.com TU_GITHUB_TOKEN
```

### Opción 2: Archivo auth.json

Crear el archivo `~/.composer/auth.json`:

```json
{
  "github-oauth": {
    "github.com": "TU_GITHUB_TOKEN"
  }
}
```

### Cómo obtener tu GitHub Token:

1. GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token
3. Scopes mínimos necesarios:
   - `read:packages` (para leer paquetes)
   - `repo` (si el repositorio es privado)
4. Copiar el token y usarlo en el paso anterior

---

## Para Microservicios Consumidores

### En el `composer.json` de cada microservicio:

```json
{
  "repositories": [
    {
      "type": "composer",
      "url": "https://composer.pkg.github.com/iseazy"
    }
  ],
  "require": {
    "iseazy/security": "^1.0"
  }
}
```

### Para probar desde una rama (testing):

```json
{
  "require": {
    "iseazy/security": "dev-feature/create-package"
  }
}
```

---

## Para CI/CD (GitHub Actions)

En el workflow de deploy, **antes** de `composer install`:

```yaml
- name: Setup Composer authentication for GitHub Packages
  run: |
    composer config --global --auth github-oauth.github.com ${{ secrets.GITHUB_TOKEN }}
```

**Nota:** `secrets.GITHUB_TOKEN` ya existe automáticamente en GitHub Actions.

---

## Publicar Nueva Versión

### Opción 1: Mediante Tag (Automático)

```bash
git tag v1.0.4
git push origin v1.0.4
```

El workflow `.github/workflows/publish-package.yml` se ejecutará automáticamente.

### Opción 2: Manualmente

Ir a GitHub → Actions → "Publish to GitHub Packages" → Run workflow

---

## Verificar que el Paquete está Publicado

1. GitHub → iseazy-microservice-security → Packages
2. Deberías ver `iseazy/security` con las versiones publicadas

---

## Troubleshooting

### Error: "Could not authenticate against github.com"

**Solución:** Configurar el token de GitHub (ver sección "Para Desarrolladores")

### Error: "Package iseazy/security not found"

**Causas posibles:**
1. El paquete no ha sido publicado a GitHub Packages
2. No tienes acceso al repositorio privado
3. No has configurado el `repositories` en composer.json

### Verificar configuración de Composer:

```bash
composer config --list --global | grep github-oauth
```

Debería mostrar tu token configurado.
