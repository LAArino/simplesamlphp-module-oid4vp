# simplesamlphp-module-oid4vp

**OID4VP Authentication Module for SimpleSAMLphp**
**Módulo de autenticación OID4VP para SimpleSAMLphp**

[![Packagist](https://img.shields.io/packagist/v/laarino/simplesamlphp-module-oid4vp)](https://packagist.org/packages/laarino/simplesamlphp-module-oid4vp)
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
- **DID resolution** — `did:key` (including the EBSI `jwk_jcs-pub` format), `did:jwk`, `did:web`, `did:ebsi`, `did:blue`
- **Trust networks** — EBSI (Pilot + RedIRIS mirror + Conformance) and BLUE (PROD/PRE/DES) built in, with per-network DID Registry and Trusted Issuers Registry, retry chains, and 48h disk cache
- **W3C Verifiable Credentials** — Supports W3C-VC in JWT format (Verifiable Presentations and Verifiable Credentials)
- **12-step verification pipeline** — VP signature, VC signature, nonce, audience, expiry, issuer trust
- **VC → SAML attribute mapping** — Friendly names (`cn`, `mail`, `eduPersonPrincipalName`) and OID format (`urn:oid:...`)
- **Responsive QR page** — QR code on desktop, deep-link button on touch devices and narrow viewports, dark-scheme aware
- **Themeable** — the QR page layout is configurable (`template_base` / `template`), so it can reuse the host theme's login layout
- **Multi-language** — English and Spanish UI
- **Flexible session storage** — File-based (with flock) or SQL via SimpleSAMLphp store

### Requirements

- PHP >= 8.0
- Extensions: `ext-openssl` (no bignum extension needed)
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

All options live in the authentication source entry above. `config/module_oid4vp.php`
documents every option with its default — it is a **reference to copy from, not a file
the module loads**:

```php
'oid4vp' => [
    'oid4vp:OID4VP',
    'verifier_id'      => 'https://idp.example.org',  // Your IdP entity ID
    'signing_key'      => 'oid4vp.pem',                // EC private key (certdir-relative)
    'signing_cert'     => 'oid4vp.crt',                // EC public key
    'session_timeout'  => 300,                         // QR timeout in seconds
    'trusted_issuers'  => [                            // Always trusted issuer DIDs
        'did:key:z6Mkr...',
    ],
    'trust_networks'   => [],                          // Override EBSI/BLUE registries
    'template_base'    => 'base.twig',                 // Layout the QR page extends
],
```

Issuers on a known network (`did:ebsi`, `did:blue`) are additionally checked against that
network's Trusted Issuers Registry and **rejected if not registered**. Issuers whose DID
method has no network (`did:key`, `did:jwk`) are accepted with a log warning when no
`trusted_issuers` list is configured — development mode, not for production.

#### 4. Create data directories

```bash
mkdir -p data/oid4vp_sessions data/oid4vp_cache
chown www-data:www-data data/oid4vp_sessions data/oid4vp_cache
chmod 700 data/oid4vp_sessions data/oid4vp_cache
```

`data/` must live **outside the document root**: session files hold the verified
credential's attributes. `data/oid4vp_cache/` stores DID documents and Trusted Issuers
Registry lookups for 48 hours.

#### 5. Theming (optional)

The QR page extends `base.twig` by default, which looks like a generic SimpleSAMLphp
page. Point `template_base` at your theme's login layout so it matches the rest of the
login flow — for RedIRIS's IdPnube theme that is `baseSSO.twig`. Themes needing more
wrapper markup can override `oid4vp:qrcode.twig` the standard way, by shipping
`themes/<Theme>/oid4vp/qrcode.twig`.

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

A presentation must carry the fields the EducationalID schema itself marks as required
(`id`, `identifier`, `eduPersonScopedAffiliation`); everything else is optional. Deployments
whose service providers need more can list them in `required_attributes` — but note that
demanding more than the schema does rejects credentials that are perfectly valid.

`eduPersonTargetedID` is derived as `md5(credentialSubject.id)`. It is stable per subject
but **not** per relying party, so it does not provide the pairwise privacy that the
attribute's name implies.

### Testing

```bash
# Install dev dependencies
composer install --dev

# Run unit tests
./vendor/bin/phpunit
```

A simulated wallet script is available at `tests/test_wallet.php` for end-to-end manual testing. See the [setup and testing guide](docs/GUIA-HABILITACION-Y-TESTING.md) for detailed instructions.

### Documentation

| Document | Contents |
|---|---|
| [Setup and testing guide](docs/GUIA-HABILITACION-Y-TESTING.md) | Full deployment walkthrough, trust network configuration, manual and unit testing, troubleshooting (Spanish) |
| [RedIRIS Docker integration](docs/INTEGRACION-REDIRIS-DOCKER.md) | What the RedIRIS team needs to do to ship this module in the dockerized IdP: image dependencies, theming, env vars, volumes (Spanish) |

### Roadmap

**Current:**
- [x] `did:key` resolution (multicodec `0x1200` and EBSI `jwk_jcs-pub` `0xeb51`)
- [x] `did:jwk` and `did:web` resolution
- [x] `did:ebsi` resolution via EBSI DID Registry (Pilot + RedIRIS mirror + Conformance)
- [x] `did:blue` resolution via BLUE DID Registry (PROD/PRE/DES chain)
- [x] EBSI and BLUE Trusted Issuers Registry integration
- [x] Static trusted issuers list
- [x] File-based and SQL session storage
- [x] Friendly name and OID attribute mapping
- [x] Mobile deep-link support

Verified end to end against BLUE and EBSI EducationalID credentials presented from a
real EUDI wallet.

**Planned:**
- [ ] StatusList2021 revocation checking
- [ ] Multiple credential types per authentication source (today one type per source)
- [ ] SD-JWT VC, DCQL and JARM (`direct_post.jwt`) support
- [ ] Per-relying-party `eduPersonTargetedID`

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
- **Resolución DID** — `did:key` (incluido el formato EBSI `jwk_jcs-pub`), `did:jwk`, `did:web`, `did:ebsi`, `did:blue`
- **Redes de confianza** — EBSI (Pilot + espejo RedIRIS + Conformance) y BLUE (PROD/PRE/DES) integradas, con Registro DID y Trusted Issuers Registry por red, cadenas de reintento y caché en disco de 48h
- **Credenciales Verificables W3C** — Soporta W3C-VC en formato JWT (Verifiable Presentations y Verifiable Credentials)
- **Pipeline de verificación de 12 pasos** — Firma VP, firma VC, nonce, audiencia, expiración, confianza del emisor
- **Mapeo VC → atributos SAML** — Nombres amigables (`cn`, `mail`, `eduPersonPrincipalName`) y formato OID (`urn:oid:...`)
- **Página QR responsiva** — Código QR en escritorio, botón deep-link en dispositivos táctiles y pantallas estrechas, compatible con modo oscuro
- **Tematizable** — El layout de la página QR es configurable (`template_base` / `template`), por lo que puede reutilizar el layout de login del tema anfitrión
- **Multi-idioma** — Interfaz en inglés y español
- **Almacenamiento de sesión flexible** — Basado en archivos (con flock) o SQL vía SimpleSAMLphp store

### Requisitos

- PHP >= 8.0
- Extensiones: `ext-openssl` (no requiere extensión de precisión arbitraria)
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

Todas las opciones van en la entrada de la fuente de autenticación anterior.
`config/module_oid4vp.php` documenta cada opción con su valor por defecto — es una
**referencia de la que copiar, no un fichero que el módulo cargue**:

```php
'oid4vp' => [
    'oid4vp:OID4VP',
    'verifier_id'      => 'https://idp.example.org',  // Entity ID del IdP
    'signing_key'      => 'oid4vp.pem',                // Clave privada EC (relativa a certdir)
    'signing_cert'     => 'oid4vp.crt',                // Clave pública EC
    'session_timeout'  => 300,                         // Timeout del QR en segundos
    'trusted_issuers'  => [                            // DIDs siempre confiables
        'did:key:z6Mkr...',
    ],
    'trust_networks'   => [],                          // Sobreescribir registros EBSI/BLUE
    'template_base'    => 'base.twig',                 // Layout que extiende la página QR
],
```

Los emisores de una red conocida (`did:ebsi`, `did:blue`) se comprueban además contra el
Trusted Issuers Registry de esa red y **se rechazan si no están registrados**. Los emisores
cuyo método DID no tiene red asociada (`did:key`, `did:jwk`) se aceptan con un warning en
el log cuando no hay lista `trusted_issuers` configurada — modo desarrollo, no para producción.

#### 4. Crear directorios de datos

```bash
mkdir -p data/oid4vp_sessions data/oid4vp_cache
chown www-data:www-data data/oid4vp_sessions data/oid4vp_cache
chmod 700 data/oid4vp_sessions data/oid4vp_cache
```

`data/` debe estar **fuera del document root**: los ficheros de sesión contienen los
atributos de la credencial ya verificada. `data/oid4vp_cache/` guarda documentos DID y
consultas al Trusted Issuers Registry durante 48 horas.

#### 5. Tematización (opcional)

La página QR extiende `base.twig` por defecto, que tiene aspecto de página genérica de
SimpleSAMLphp. Apuntar `template_base` al layout de login del tema propio para que encaje
con el resto del flujo — en el tema IdPnube de RedIRIS es `baseSSO.twig`. Los temas que
necesiten más envoltorio pueden sobreescribir `oid4vp:qrcode.twig` por la vía estándar,
publicando `themes/<Tema>/oid4vp/qrcode.twig`.

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

Una presentación debe traer los campos que el propio esquema EducationalID marca como
obligatorios (`id`, `identifier`, `eduPersonScopedAffiliation`); el resto son opcionales.
Los despliegues cuyos proveedores de servicio necesiten más pueden declararlos en
`required_attributes` — pero exigir más que el esquema rechaza credenciales válidas.

`eduPersonTargetedID` se deriva como `md5(credentialSubject.id)`. Es estable por sujeto
pero **no** por proveedor de servicio, así que no aporta la privacidad por pares que
sugiere el nombre del atributo.

### Testing

```bash
# Instalar dependencias de desarrollo
composer install --dev

# Ejecutar tests unitarios
./vendor/bin/phpunit
```

Hay un script de wallet simulada en `tests/test_wallet.php` para testing manual end-to-end. Consultar la [guía de habilitación y testing](docs/GUIA-HABILITACION-Y-TESTING.md) para instrucciones detalladas.

### Documentación

| Documento | Contenido |
|---|---|
| [Guía de habilitación y testing](docs/GUIA-HABILITACION-Y-TESTING.md) | Despliegue completo, configuración de redes de confianza, testing manual y unitario, diagnóstico de problemas |
| [Integración en el Docker de RedIRIS](docs/INTEGRACION-REDIRIS-DOCKER.md) | Qué debe hacer el equipo de RedIRIS para incluir el módulo en el IdP dockerizado: dependencias de la imagen, tematización, variables de entorno, volúmenes |

### Hoja de ruta

**Actual:**
- [x] Resolución `did:key` (multicodec `0x1200` y EBSI `jwk_jcs-pub` `0xeb51`)
- [x] Resolución `did:jwk` y `did:web`
- [x] Resolución `did:ebsi` vía EBSI DID Registry (Pilot + espejo RedIRIS + Conformance)
- [x] Resolución `did:blue` vía BLUE DID Registry (cadena PROD/PRE/DES)
- [x] Integración con los Trusted Issuers Registry de EBSI y BLUE
- [x] Lista estática de emisores confiables
- [x] Almacenamiento de sesión en archivos y SQL
- [x] Mapeo de atributos en nombres amigables y OID
- [x] Soporte deep-link en móvil

Verificado de extremo a extremo con credenciales EducationalID de BLUE y de EBSI
presentadas desde una wallet EUDI real.

**Planificado:**
- [ ] Verificación de revocación StatusList2021
- [ ] Varios tipos de credencial por fuente de autenticación (hoy, uno por fuente)
- [ ] Soporte SD-JWT VC, DCQL y JARM (`direct_post.jwt`)
- [ ] `eduPersonTargetedID` por proveedor de servicio

### Licencia

[European Union Public Licence v1.2 (EUPL-1.2)](LICENSE)
