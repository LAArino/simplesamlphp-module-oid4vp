# simplesamlphp-module-oid4vp

**OID4VP Authentication Module for SimpleSAMLphp**
**Módulo de autenticación OID4VP para SimpleSAMLphp**

[![PHP >= 8.0](https://img.shields.io/badge/PHP-%3E%3D%208.0-blue)](https://www.php.net/)
[![SimpleSAMLphp >= 2.0](https://img.shields.io/badge/SimpleSAMLphp-%3E%3D%202.0-orange)](https://simplesamlphp.org/)
[![License: EUPL-1.2](https://img.shields.io/badge/License-EUPL--1.2-green)](LICENSE)

---

[English](#english) | [Español](#español)

---

## English

### Overview

SimpleSAMLphp authentication source that enables identity providers to authenticate users via **OpenID for Verifiable Presentations (OID4VP)**. Users present **W3C Verifiable Credentials** from a compatible **Wallet** by scanning a QR code, and the module verifies the credential and maps it to SAML attributes.

Designed for universities and educational institutions.

### Authentication Flow

```
┌─────────┐         ┌──────────┐         ┌────────┐
│ Browser  │         │   IdP    │         │ Wallet │
│          │         │ (module) │         │        │
└────┬─────┘         └────┬─────┘         └───┬────┘
     │  1. Select OID4VP  │                      │
     │───────────────────>│                      │
     │  2. QR code page   │                      │
     │<───────────────────│                      │
     │                    │                      │
     │  3. Scan QR / deep-link                   │
     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ >│
     │                    │  4. GET /request_uri  │
     │                    │<─────────────────────│
     │                    │  5. Signed JAR (JWT)  │
     │                    │─────────────────────>│
     │                    │  6. POST /direct_post │
     │                    │  (vp_token + state)   │
     │                    │<─────────────────────│
     │                    │  7. Verify VP + VC    │
     │                    │  8. 200 OK            │
     │                    │─────────────────────>│
     │  9. Poll /status   │                      │
     │───────────────────>│                      │
     │  10. completed     │                      │
     │<───────────────────│                      │
     │  11. SAML Assertion│                      │
     │<───────────────────│                      │
```

### Features

- **OID4VP protocol** — JWT Authorization Request (JAR) + Direct Post response mode
- **ES256 cryptography** — P-256 elliptic curve for JWT signing and verification
- **DID resolution** — `did:key` (day 1), `did:ebsi` (planned)
- **W3C Verifiable Credentials** — Supports W3C-VC in JWT format (Verifiable Presentations and Verifiable Credentials)
- **12-step verification pipeline** — VP signature, VC signature, nonce, audience, expiry, issuer trust
- **VC → SAML attribute mapping** — Friendly names (`cn`, `mail`, `eduPersonPrincipalName`) and OID format (`urn:oid:...`)
- **Responsive QR page** — QR code on desktop, deep-link button on mobile
- **Multi-language** — English and Spanish UI
- **Flexible session storage** — File-based (with flock) or SQL via SimpleSAMLphp store

### Requirements

- PHP >= 8.0
- Extensions: `ext-gmp`, `ext-openssl`
- SimpleSAMLphp >= 2.0
- HTTPS with valid certificate
- `/direct_post` endpoint accessible from the wallet network

### Installation

```bash
composer require laarino/simplesamlphp-module-oid4vp
```

The module auto-enables via the `default-enable` file.

### Configuration

#### 1. Generate EC P-256 keys

```bash
openssl ecparam -name prime256v1 -genkey -noout -out cert/oid4vp.pem
openssl ec -in cert/oid4vp.pem -pubout -out cert/oid4vp.crt
```

These keys are **separate** from the SAML signing keys.

#### 2. Add authentication source

In `config/authsources.php`:

```php
'oid4vp' => [
    'oid4vp:OID4VP',
],
```

Or use it within a `multiauth` source:

```php
'default-sp' => [
    'saml:SP',
    'idp' => 'https://idp.example.org',
],
'multi' => [
    'multiauth:MultiAuth',
    'sources' => ['default-sp', 'oid4vp'],
],
```

#### 3. Module configuration

Copy `config/module_oid4vp.php` to your SimpleSAMLphp `config/` directory and edit:

```php
'verifier_client_id' => 'https://idp.example.org',  // Your IdP entity ID
'private_key_path'   => 'cert/oid4vp.pem',           // Path to EC private key
'public_key_path'    => 'cert/oid4vp.crt',           // Path to EC public key
'session_ttl'        => 300,                          // QR timeout in seconds
'trusted_issuers'    => [                             // Trusted credential issuer DIDs
    'did:key:z6Mkr...',
],
```

#### 4. Create session directory

```bash
mkdir -p data/oid4vp_sessions
chown www-data:www-data data/oid4vp_sessions
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/module.php/oid4vp/qrpage` | QR code page / auth completion |
| GET | `/module.php/oid4vp/request_uri/{id}` | Signed JWT Authorization Request |
| POST | `/module.php/oid4vp/direct_post` | Receives VP token from wallet |
| GET | `/module.php/oid4vp/status/{id}` | Session status polling (JSON) |

### Attribute Mapping

The module maps `credentialSubject` fields from the Verifiable Credential to SAML attributes:

| VC Field | SAML Friendly Name | SAML OID |
|----------|-------------------|----------|
| `currentGivenName` | `givenName` | `urn:oid:2.5.4.42` |
| `currentFamilyName` | `sn` | `urn:oid:2.5.4.4` |
| `displayName` | `cn` / `displayName` | `urn:oid:2.5.4.3` / `urn:oid:2.16.840.1.113730.3.1.241` |
| `mail` | `mail` | `urn:oid:0.9.2342.19200300.100.1.3` |
| `eduPersonPrincipalName` | `eduPersonPrincipalName` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.6` |
| `schacHomeOrganization` | `schacHomeOrganization` | `urn:oid:1.3.6.1.4.1.25178.1.2.9` |
| `eduPersonAffiliation` | `eduPersonAffiliation` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` |
| `eduPersonScopedAffiliation` | `eduPersonScopedAffiliation` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.9` |
| `schacPersonalUniqueCode` | `schacPersonalUniqueCode` | `urn:oid:1.3.6.1.4.1.25178.1.2.14` |

Custom mappings can be defined in the `attribute_map` configuration option.

### Testing

```bash
# Install dev dependencies
composer install --dev

# Run unit tests
./vendor/bin/phpunit
```

A simulated wallet script is available at `tests/test_wallet.php` for end-to-end manual testing. See the [setup and testing guide](docs/GUIA-HABILITACION-Y-TESTING.md) for detailed instructions.

### Roadmap

**Day 1 (current):**
- [x] `did:key` resolution
- [x] Static trusted issuers list
- [x] File-based and SQL session storage
- [x] Friendly name and OID attribute mapping
- [x] Mobile deep-link support

**Day 2+ (planned):**
- [ ] `did:ebsi` resolution via EBSI DID Registry
- [ ] EBSI Trusted Issuers Registry integration
- [ ] StatusList2021 revocation checking
- [ ] Multiple credential type support

### License

[European Union Public Licence v1.2 (EUPL-1.2)](LICENSE)

---

## Español

### Descripción

Fuente de autenticación para SimpleSAMLphp que permite a los proveedores de identidad autenticar usuarios mediante **OpenID for Verifiable Presentations (OID4VP)**. Los usuarios presentan **Credenciales Verificables W3C (W3C-VC)** desde una **Wallet** compatible escaneando un código QR, y el módulo verifica la credencial y la mapea a atributos SAML.

Diseñado para universidades e instituciones educativas.

### Flujo de autenticación

```
┌───────────┐       ┌──────────┐       ┌────────┐
│ Navegador │       │   IdP    │       │ Wallet │
│           │       │ (módulo) │       │        │
└─────┬─────┘       └────┬─────┘       └───┬────┘
      │ 1. Seleccionar    │                    │
      │    OID4VP         │                    │
      │──────────────────>│                    │
      │ 2. Página QR      │                    │
      │<──────────────────│                    │
      │                   │                    │
      │ 3. Escanear QR / deep-link             │
      │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>│
      │                   │ 4. GET /request_uri│
      │                   │<───────────────────│
      │                   │ 5. JAR firmado     │
      │                   │───────────────────>│
      │                   │ 6. POST            │
      │                   │    /direct_post    │
      │                   │<───────────────────│
      │                   │ 7. Verificar VP+VC │
      │                   │ 8. 200 OK          │
      │                   │───────────────────>│
      │ 9. Consultar      │                    │
      │    /status         │                    │
      │──────────────────>│                    │
      │ 10. completado    │                    │
      │<──────────────────│                    │
      │ 11. Aserción SAML │                    │
      │<──────────────────│                    │
```

### Características

- **Protocolo OID4VP** — JWT Authorization Request (JAR) + modo de respuesta Direct Post
- **Criptografía ES256** — Curva elíptica P-256 para firma y verificación de JWT
- **Resolución DID** — `did:key` (día 1), `did:ebsi` (planificado)
- **Credenciales Verificables W3C** — Soporta W3C-VC en formato JWT (Verifiable Presentations y Verifiable Credentials)
- **Pipeline de verificación de 12 pasos** — Firma VP, firma VC, nonce, audiencia, expiración, confianza del emisor
- **Mapeo VC → atributos SAML** — Nombres amigables (`cn`, `mail`, `eduPersonPrincipalName`) y formato OID (`urn:oid:...`)
- **Página QR responsiva** — Código QR en escritorio, botón deep-link en móvil
- **Multi-idioma** — Interfaz en inglés y español
- **Almacenamiento de sesión flexible** — Basado en archivos (con flock) o SQL vía SimpleSAMLphp store

### Requisitos

- PHP >= 8.0
- Extensiones: `ext-gmp`, `ext-openssl`
- SimpleSAMLphp >= 2.0
- HTTPS con certificado válido
- Endpoint `/direct_post` accesible desde la red de la wallet

### Instalación

```bash
composer require laarino/simplesamlphp-module-oid4vp
```

El módulo se habilita automáticamente mediante el archivo `default-enable`.

### Configuración

#### 1. Generar claves EC P-256

```bash
openssl ecparam -name prime256v1 -genkey -noout -out cert/oid4vp.pem
openssl ec -in cert/oid4vp.pem -pubout -out cert/oid4vp.crt
```

Estas claves son **independientes** de las claves de firma SAML.

#### 2. Añadir fuente de autenticación

En `config/authsources.php`:

```php
'oid4vp' => [
    'oid4vp:OID4VP',
],
```

O dentro de una fuente `multiauth`:

```php
'default-sp' => [
    'saml:SP',
    'idp' => 'https://idp.example.org',
],
'multi' => [
    'multiauth:MultiAuth',
    'sources' => ['default-sp', 'oid4vp'],
],
```

#### 3. Configuración del módulo

Copiar `config/module_oid4vp.php` al directorio `config/` de SimpleSAMLphp y editar:

```php
'verifier_client_id' => 'https://idp.example.org',  // Entity ID del IdP
'private_key_path'   => 'cert/oid4vp.pem',           // Ruta a la clave privada EC
'public_key_path'    => 'cert/oid4vp.crt',           // Ruta a la clave pública EC
'session_ttl'        => 300,                          // Timeout del QR en segundos
'trusted_issuers'    => [                             // DIDs de emisores confiables
    'did:key:z6Mkr...',
],
```

#### 4. Crear directorio de sesiones

```bash
mkdir -p data/oid4vp_sessions
chown www-data:www-data data/oid4vp_sessions
```

### Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/module.php/oid4vp/qrpage` | Página QR / completar autenticación |
| GET | `/module.php/oid4vp/request_uri/{id}` | JWT Authorization Request firmado |
| POST | `/module.php/oid4vp/direct_post` | Recibe VP token de la wallet |
| GET | `/module.php/oid4vp/status/{id}` | Consulta de estado de sesión (JSON) |

### Mapeo de atributos

El módulo mapea los campos `credentialSubject` de la Verifiable Credential a atributos SAML:

| Campo VC | Nombre SAML amigable | OID SAML |
|----------|---------------------|----------|
| `currentGivenName` | `givenName` | `urn:oid:2.5.4.42` |
| `currentFamilyName` | `sn` | `urn:oid:2.5.4.4` |
| `displayName` | `cn` / `displayName` | `urn:oid:2.5.4.3` / `urn:oid:2.16.840.1.113730.3.1.241` |
| `mail` | `mail` | `urn:oid:0.9.2342.19200300.100.1.3` |
| `eduPersonPrincipalName` | `eduPersonPrincipalName` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.6` |
| `schacHomeOrganization` | `schacHomeOrganization` | `urn:oid:1.3.6.1.4.1.25178.1.2.9` |
| `eduPersonAffiliation` | `eduPersonAffiliation` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` |
| `eduPersonScopedAffiliation` | `eduPersonScopedAffiliation` | `urn:oid:1.3.6.1.4.1.5923.1.1.1.9` |
| `schacPersonalUniqueCode` | `schacPersonalUniqueCode` | `urn:oid:1.3.6.1.4.1.25178.1.2.14` |

Se pueden definir mapeos personalizados en la opción de configuración `attribute_map`.

### Testing

```bash
# Instalar dependencias de desarrollo
composer install --dev

# Ejecutar tests unitarios
./vendor/bin/phpunit
```

Hay un script de wallet simulada en `tests/test_wallet.php` para testing manual end-to-end. Consultar la [guía de habilitación y testing](docs/GUIA-HABILITACION-Y-TESTING.md) para instrucciones detalladas.

### Hoja de ruta

**Día 1 (actual):**
- [x] Resolución `did:key`
- [x] Lista estática de emisores confiables
- [x] Almacenamiento de sesión en archivos y SQL
- [x] Mapeo de atributos en nombres amigables y OID
- [x] Soporte deep-link en móvil

**Día 2+ (planificado):**
- [ ] Resolución `did:ebsi` vía EBSI DID Registry
- [ ] Integración con EBSI Trusted Issuers Registry
- [ ] Verificación de revocación StatusList2021
- [ ] Soporte para múltiples tipos de credencial

### Licencia

[European Union Public Licence v1.2 (EUPL-1.2)](LICENSE)
