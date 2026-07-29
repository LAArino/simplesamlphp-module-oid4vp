# Guia de habilitacion y testing del modulo OID4VP

## Indice

1. [Requisitos previos](#1-requisitos-previos)
2. [Generar claves ES256 para el verificador](#2-generar-claves-es256-para-el-verificador)
3. [Instalar dependencias PHP](#3-instalar-dependencias-php)
4. [Configurar SimpleSAMLphp](#4-configurar-simplesamlphp)
5. [Verificar que el modulo esta habilitado](#5-verificar-que-el-modulo-esta-habilitado)
6. [Crear directorios de datos](#6-crear-directorios-de-datos)
7. [Test manual: flujo completo con wallet simulada](#7-test-manual-flujo-completo-con-wallet-simulada)
8. [Tests unitarios con PHPUnit](#8-tests-unitarios-con-phpunit)
9. [Verificar la SAML assertion resultante](#9-verificar-la-saml-assertion-resultante)
10. [Casos de error a probar](#10-casos-de-error-a-probar)
11. [Diagnostico de problemas](#11-diagnostico-de-problemas)

---

## 1. Requisitos previos

### Software

| Requisito | Version minima | Verificar con |
|---|---|---|
| PHP | 8.0+ | `php -v` |
| ext-openssl | * | `php -m \| grep openssl` |
| ext-json | * | `php -m \| grep json` |
| SimpleSAMLphp | 2.0+ | Ver `config/config.php` |
| Composer | 2.x | `composer --version` |
| curl | * | `curl --version` |
| openssl CLI | * | `openssl version` |

> **Nota sobre `ext-gmp`**: versiones anteriores del modulo la requerian para decodificar
> base58 (resolucion de `did:key`). Ya no se necesita: el modulo implementa base58
> internamente sin librerias de precision arbitraria, de modo que instala en imagenes
> PHP que no incluyen ni `gmp` ni `bcmath`.

### Conectividad de red saliente

La verificacion de credenciales de las redes EBSI y BLUE requiere acceso HTTPS saliente
desde el IdP a los registros de cada red. Si hay cortafuegos o proxy de salida, hay que
permitir estos destinos:

| Red | Destinos |
|---|---|
| EBSI | `api-pilot.ebsi.eu`, `api-pilot.ebsi.rediris.es` (espejo), `api-conformance.ebsi.eu` |
| BLUE | `api.blue.rediris.es`, `api-pre.blue.rediris.es`, `api-des.blue.rediris.es` |

Sin esta conectividad solo funcionan los emisores resueltos localmente (`did:key`, `did:jwk`)
y los declarados en la lista estatica `trusted_issuers`.

---

## 2. Generar claves ES256 para el verificador

Las claves ES256 (P-256/prime256v1) son **separadas** de las claves SAML RSA del IdP. Se usan exclusivamente para firmar los JWT Authorization Request (JAR) del protocolo OID4VP.

```bash
# Posicionarse en el directorio cert/ de SimpleSAMLphp
cd /var/www/html/simplesamlphp/cert/

# Generar clave privada EC P-256
openssl ecparam -name prime256v1 -genkey -noout -out oid4vp.pem

# Extraer clave publica
openssl ec -in oid4vp.pem -pubout -out oid4vp.crt

# Permisos restrictivos (solo lectura por el usuario de Apache)
chmod 600 oid4vp.pem
chown www-data:www-data oid4vp.pem oid4vp.crt

# Verificar que la clave es P-256
openssl ec -in oid4vp.pem -text -noout 2>&1 | head -1
# Debe mostrar: ASN1 OID: prime256v1
```

### Generar tambien un par de claves de test (para simular la wallet/issuer)

```bash
# Clave del "issuer" de test (quien emitio el EducationalID)
openssl ecparam -name prime256v1 -genkey -noout -out test_issuer.pem
openssl ec -in test_issuer.pem -pubout -out test_issuer_pub.pem

# Clave del "holder" de test (el usuario/wallet)
openssl ecparam -name prime256v1 -genkey -noout -out test_holder.pem
openssl ec -in test_holder.pem -pubout -out test_holder_pub.pem
```

---

## 3. Instalar dependencias PHP

```bash
cd /var/www/html/simplesamlphp/modules/oid4vp/
composer install

# Verificar que se instalaron
composer show firebase/php-jwt
composer show guzzlehttp/guzzle
composer show ramsey/uuid
```

Si el modulo se gestiona como parte del proyecto principal de SimpleSAMLphp, se puede instalar desde la raiz:

```bash
cd /var/www/html/simplesamlphp/
composer require laarino/simplesamlphp-module-oid4vp
```

---

## 4. Configurar SimpleSAMLphp

### 4.1 authsources.php

Editar `/var/www/html/simplesamlphp/config/authsources.php`:

```php
$config = [

    'admin' => ['core:AdminPassword'],

    // MultiAuth: ofrece ambas opciones de login
    'multiauth' => [
        'multiauth:MultiAuth',
        'sources' => [
            'ldap' => [
                'text' => [
                    'es' => 'Usuario y contrasena',
                    'en' => 'Username and password',
                ],
            ],
            'oid4vp' => [
                'text' => [
                    'es' => 'Presentar EducationalID desde tu Cartera EUDI',
                    'en' => 'Present EducationalID from your EUDI Wallet',
                ],
            ],
        ],
    ],

    // Auth source LDAP existente
    'ldap' => [
        'ldap:LDAP',
        // ... tu configuracion LDAP existente ...
    ],

    // Auth source OID4VP (nuevo)
    'oid4vp' => [
        'oid4vp:OID4VP',

        // CAMBIAR a tu entity ID real
        'verifier_id' => 'https://idp.tuuniversidad.es',

        // Claves ES256 (generadas en paso 2)
        'signing_cert' => 'cert/oid4vp.crt',
        'signing_key'  => 'cert/oid4vp.pem',

        // Timeout del QR (5 minutos)
        'session_timeout' => 300,

        // false = nombres amigables (cn, sn, mail...)
        // true  = formato OID (urn:oid:2.5.4.3, ...)
        'use_oid_format' => false,

        // Lista estatica de issuers de confianza. Se comprueba SIEMPRE primero,
        // antes que cualquier registro de red.
        'trusted_issuers' => [
            // 'did:ebsi:z...',
            // 'did:blue:z...',
        ],

        // Redes de confianza. EBSI (did:ebsi) y BLUE (did:blue) vienen incorporadas
        // con sus registros por defecto; solo hay que rellenar esto para sobreescribir
        // una red o anadir una nueva. Ver seccion 4.3.
        'trust_networks' => [],

        // Campos que debe traer la credencial. Por defecto, los que el esquema
        // EducationalID marca como obligatorios (id, identifier,
        // eduPersonScopedAffiliation). Exigir mas rechaza credenciales validas.
        // 'required_attributes' => ['id', 'identifier', 'eduPersonScopedAffiliation'],

        // Layout que extiende la pagina QR. Apuntarlo al layout de login del tema
        // propio para que la pantalla QR no desentone con la de usuario/contrasena.
        'template_base' => 'base.twig',
    ],
];
```

### 4.3 Redes de confianza (EBSI y BLUE)

El modulo selecciona el registro segun el metodo del DID del emisor, con cadenas de
reintento equivalentes a las de la wallet:

| Metodo DID | Red | Primario | Reserva (error de red) | Alternativas (404) |
|---|---|---|---|---|
| `did:ebsi` | EBSI | `api-pilot.ebsi.eu` | `api-pilot.ebsi.rediris.es` | `api-conformance.ebsi.eu` |
| `did:blue` | BLUE | `api.blue.rediris.es` | — | `api-pre...`, `api-des...` |

Cada red aporta Registro DID y Trusted Issuers Registry (TIR). Las resoluciones correctas
se cachean 48 h en disco.

**Semantica de confianza** (por orden):

1. DID en `trusted_issuers` → aceptado.
2. DID de una red conocida (`did:ebsi`, `did:blue`) → se consulta su TIR. **Si no esta
   registrado, se rechaza.**
3. DID sin red asociada (`did:key`, `did:jwk`, `did:web`) → si no hay `trusted_issuers`
   ni `ebsi_trust_registry`, se acepta con un WARNING en el log (**modo desarrollo:
   no usar en produccion**).

Para apuntar a un entorno concreto, sobreescribir la entrada de esa red:

```php
'trust_networks' => [
    'did:blue' => [
        'name' => 'BLUE',
        'config' => [
            'did_registry_url' => 'https://api-pre.blue.rediris.es/did-registry/v5',
            'trusted_issuers_registry_url' => 'https://api-pre.blue.rediris.es/trusted-issuers-registry/v5',
            'trusted_schemas_registry_url' => 'https://api-pre.blue.rediris.es/trusted-schemas-registry/v3',
            'label' => 'PRE',
        ],
        'alternate_configs' => [],   // sin cadena de reintento
    ],
],
```

### 4.4 Metodos DID soportados

| Metodo | Resolucion |
|---|---|
| `did:key` | Local. Multicodec `0x1200` (P-256 comprimida) y `0xeb51` (`jwk_jcs-pub`, formato EBSI) |
| `did:jwk` | Local (JWK embebida en el DID) |
| `did:web` | HTTPS segun la especificacion W3C, validando que el `id` del documento coincida |
| `did:ebsi`, `did:blue` | Registro DID de su red |
| Otros | Universal Resolver (`dev.uniresolver.io`) — **solo desarrollo** |

### 4.2 saml20-idp-hosted.php

Verificar que el IdP usa MultiAuth:

```php
$metadata['__DYNAMIC:1__'] = [
    'host' => '__DEFAULT__',
    'auth' => 'multiauth',      // <-- debe apuntar a 'multiauth'
    'privatekey'  => 'idp.pem',
    'certificate' => 'idp.crt',
    // ... resto de config ...
];
```

---

## 5. Verificar que el modulo esta habilitado

El fichero `modules/oid4vp/default-enable` indica auto-activacion. Verificar:

```bash
# El fichero debe existir
ls -la /var/www/html/simplesamlphp/modules/oid4vp/default-enable

# Verificar en la UI de admin de SimpleSAMLphp:
# https://tu-idp/simplesaml/module.php/core/frontpage_welcome.php
# -> Pestana "Configuracion" -> "Modulos" -> oid4vp debe aparecer habilitado
```

Si no se ve habilitado, crear el fichero:

```bash
touch /var/www/html/simplesamlphp/modules/oid4vp/default-enable
```

---

## 6. Crear directorios de datos

El modulo usa dos directorios bajo el `datadir` de SimpleSAMLphp:

| Directorio | Contenido |
|---|---|
| `data/oid4vp_sessions/` | Sesiones OID4VP: nonce, state, configuracion del verificador y, tras la verificacion, los atributos de la credencial |
| `data/oid4vp_cache/` | Cache de documentos DID y consultas al TIR (TTL 48 h) |

```bash
# Crear los directorios
mkdir -p /var/www/html/simplesamlphp/data/oid4vp_sessions
mkdir -p /var/www/html/simplesamlphp/data/oid4vp_cache

# Permisos: solo Apache puede leer/escribir
chown www-data:www-data /var/www/html/simplesamlphp/data/oid4vp_sessions
chown www-data:www-data /var/www/html/simplesamlphp/data/oid4vp_cache
chmod 700 /var/www/html/simplesamlphp/data/oid4vp_sessions
chmod 700 /var/www/html/simplesamlphp/data/oid4vp_cache
```

> **Importante**: `datadir` **debe quedar fuera del document root**. Los ficheros de sesion
> contienen los atributos de la credencial ya verificada. El modulo resuelve la ruta con
> `Configuration::getPathValue()`, que la interpreta respecto al directorio base de
> SimpleSAMLphp; si `datadir` apunta dentro de `public/`, esos ficheros quedarian servidos
> por HTTP. Comprobacion rapida tras un flujo de prueba:
>
> ```bash
> ls /var/www/html/simplesamlphp/public/data 2>/dev/null && echo "PROBLEMA: datadir dentro del docroot"
> ```

> **Nota**: Si SimpleSAMLphp tiene configurado `store.type => 'sql'` en `config/config.php`, el modulo usara automaticamente la base de datos SQL para las sesiones en lugar de ficheros. La cache sigue siendo en disco.

---

## 7. Test manual: flujo completo con wallet simulada

Este es el test mas importante. Simula el comportamiento de una EUDI Wallet usando `curl` y un script PHP.

### 7.1 Iniciar el flujo desde el navegador

1. Abrir el navegador y acceder a un SP que use tu IdP (o usar el test SP de SimpleSAMLphp)
2. En la pantalla de MultiAuth, seleccionar **"Presentar EducationalID"**
3. Se muestra la pagina QR con:
   - Un codigo QR
   - Un temporizador (5:00)
   - El estado "Esperando presentacion de credencial..."

4. **Anotar** de la pagina (inspeccionando la fuente o la consola JS):
   - `sessionId`: el UUID de la sesion
   - `openidUri`: el URI `openid://...`
   - `authState`: el ID de estado SSP
   - `statusUrl`: la URL de polling

### 7.2 Crear un script de wallet simulada

Crear el fichero `test_wallet.php` en cualquier directorio:

```php
<?php
/**
 * Wallet simulada para testing OID4VP.
 *
 * Uso:
 *   php test_wallet.php <request_uri_url>
 *
 * Ejemplo:
 *   php test_wallet.php "https://idp.example.org/simplesaml/module.php/oid4vp/request_uri/550e8400-e29b-41d4-a716-446655440000"
 */

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;

if ($argc < 2) {
    echo "Uso: php test_wallet.php <request_uri_url>\n";
    exit(1);
}

$requestUriUrl = $argv[1];

// --- Paso 1: Descargar el JWT Authorization Request (JAR) ---
echo "=== Paso 1: GET request_uri ===\n";
echo "URL: $requestUriUrl\n\n";

$ch = curl_init($requestUriUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Solo para testing local
$jarJwt = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode !== 200) {
    echo "ERROR: HTTP $httpCode\n$jarJwt\n";
    exit(1);
}

echo "JAR recibido (primeros 100 chars): " . substr($jarJwt, 0, 100) . "...\n\n";

// Decodificar JAR (sin verificar firma — somos la wallet de test)
$parts = explode('.', $jarJwt);
$jarPayload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

echo "JAR claims:\n";
echo "  iss:           " . ($jarPayload['iss'] ?? '-') . "\n";
echo "  aud:           " . ($jarPayload['aud'] ?? '-') . "\n";
echo "  response_type: " . ($jarPayload['response_type'] ?? '-') . "\n";
echo "  response_mode: " . ($jarPayload['response_mode'] ?? '-') . "\n";
echo "  response_uri:  " . ($jarPayload['response_uri'] ?? '-') . "\n";
echo "  nonce:         " . ($jarPayload['nonce'] ?? '-') . "\n";
echo "  state:         " . ($jarPayload['state'] ?? '-') . "\n";
echo "  exp:           " . date('Y-m-d H:i:s', $jarPayload['exp'] ?? 0) . "\n\n";

$nonce = $jarPayload['nonce'];
$state = $jarPayload['state'];
$responseUri = $jarPayload['response_uri'];
$verifierId = $jarPayload['iss'];

// --- Paso 2: Construir VP + VC de test ---
echo "=== Paso 2: Construir VP con EducationalID ===\n";

// Generar claves EC de test en memoria
$issuerKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
$holderKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);

// Credencial EducationalID de test
$now = time();
$vcPayload = [
    'iss' => 'did:key:zTestIssuer123',
    'sub' => 'did:key:zTestHolder456',
    'iat' => $now,
    'exp' => $now + 86400,
    'vc' => [
        '@context' => ['https://www.w3.org/2018/credentials/v1'],
        'type' => ['VerifiableCredential', 'VerifiableEducationalID'],
        'issuer' => 'did:key:zTestIssuer123',
        'issuanceDate' => date('c', $now),
        'credentialSubject' => [
            'id' => 'did:key:zTestHolder456',
            'eduPersonPrincipalName' => 'jgarcia@universidad.es',
            'schacHomeOrganization' => 'universidad.es',
            'eduPersonScopedAffiliation' => 'student@universidad.es',
            'eduPersonPrimaryAffiliation' => 'student',
            'eduPersonAffiliation' => 'student',
            'eduPersonAssurance' => 'https://refeds.org/assurance/IAP/low',
            'displayName' => 'Juan Garcia Lopez',
            'commonName' => 'Juan Garcia Lopez',
            'familyName' => 'Garcia Lopez',
            'firstName' => 'Juan',
            'mail' => 'jgarcia@universidad.es',
            'schacPersonalUniqueCode' => 'urn:schac:personalUniqueCode:int:esi:' . md5('jgarcia@universidad.es'),
            'identifier' => 'jgarcia',
        ],
    ],
];

// Firmar VC JWT
$vcJwt = JWT::encode($vcPayload, $issuerKey, 'ES256', null, [
    'alg' => 'ES256',
    'typ' => 'JWT',
    'kid' => 'did:key:zTestIssuer123#key-1',
]);

echo "VC JWT generado (" . strlen($vcJwt) . " bytes)\n";
echo "  Tipo: VerifiableEducationalID\n";
echo "  Subject: jgarcia@universidad.es\n\n";

// Construir VP que envuelve la VC
$vpPayload = [
    'iss' => 'did:key:zTestHolder456',
    'aud' => $verifierId,
    'nonce' => $nonce,
    'iat' => $now,
    'exp' => $now + 300,
    'vp' => [
        '@context' => ['https://www.w3.org/2018/credentials/v1'],
        'type' => ['VerifiablePresentation'],
        'verifiableCredential' => [$vcJwt],
    ],
];

$vpJwt = JWT::encode($vpPayload, $holderKey, 'ES256', null, [
    'alg' => 'ES256',
    'typ' => 'JWT',
    'kid' => 'did:key:zTestHolder456#key-1',
]);

echo "VP JWT generado (" . strlen($vpJwt) . " bytes)\n";
echo "  aud:   $verifierId\n";
echo "  nonce: $nonce\n\n";

// Presentation submission (describe donde esta la VC dentro de la VP)
$presentationSubmission = json_encode([
    'id' => 'test-submission',
    'definition_id' => 'educationalid-presentation',
    'descriptor_map' => [
        [
            'id' => 'educationalid-descriptor',
            'format' => 'jwt_vp',
            'path' => '$',
            'path_nested' => [
                'format' => 'jwt_vc',
                'path' => '$.vp.verifiableCredential[0]',
            ],
        ],
    ],
]);

// --- Paso 3: POST direct_post ---
echo "=== Paso 3: POST direct_post ===\n";
echo "URL: $responseUri\n";
echo "Params: vp_token=<jwt>, state=$state, presentation_submission=<json>\n\n";

$ch = curl_init($responseUri);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'vp_token' => $vpJwt,
    'presentation_submission' => $presentationSubmission,
    'state' => $state,
]));
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "Respuesta: HTTP $httpCode\n";
echo "$response\n\n";

if ($httpCode === 200) {
    echo "*** EXITO: VP verificada correctamente ***\n";
    echo "El navegador deberia detectar 'completed' en el siguiente poll y completar la autenticacion.\n";
} else {
    echo "*** ERROR: La verificacion fallo ***\n";
    echo "Revisa los logs de SimpleSAMLphp para mas detalles.\n";
}
```

### 7.3 Ejecutar el test

```bash
# 1. Desde el navegador, iniciar el flujo OID4VP y anotar la URL del request_uri
#    (visible en el QR o en window.oid4vpConfig.openidUri en la consola JS)

# 2. Extraer la request_uri del openidUri:
#    openid://?request_uri=https%3A%2F%2Fidp.example.org%2Fsimplesaml%2Fmodule.php%2Foid4vp%2Frequest_uri%2F<session-id>

# 3. Ejecutar la wallet simulada
cd /var/www/html/simplesamlphp/modules/oid4vp/
php test_wallet.php "https://idp.example.org/simplesaml/module.php/oid4vp/request_uri/<session-id>"
```

### 7.4 Que esperar

Si todo funciona correctamente:

1. La wallet simulada muestra:
   ```
   === Paso 1: GET request_uri ===
   JAR recibido...
   JAR claims:
     iss:           https://idp.example.org
     response_type: vp_token
     ...

   === Paso 2: Construir VP con EducationalID ===
   VC JWT generado (1234 bytes)
   VP JWT generado (2345 bytes)

   === Paso 3: POST direct_post ===
   Respuesta: HTTP 200
   {"status":"ok"}

   *** EXITO: VP verificada correctamente ***
   ```

2. En el navegador, el polling detecta `completed` y redirige automaticamente
3. SimpleSAMLphp genera la SAML assertion con los atributos mapeados

> **IMPORTANTE**: El script de test genera claves en memoria, por lo que el DID `did:key:zTestIssuer123` no es un `did:key` real resolvible. Para que la verificacion completa funcione, la configuracion debe tener `trusted_issuers` vacio y `ebsi_trust_registry` a `null` (modo desarrollo, acepta cualquier issuer con warning en los logs).

### 7.5 Test con curl manual (paso a paso)

Si prefieres hacer cada paso por separado con curl:

```bash
# Variable base
BASE="https://idp.example.org/simplesaml/module.php/oid4vp"
SESSION_ID="<el-uuid-de-la-sesion>"

# Paso 1: Obtener el JAR
curl -k -s "$BASE/request_uri/$SESSION_ID" \
  -H "Accept: application/oauth-authz-req+jwt" \
  -o jar.jwt

# Inspeccionar el JAR (decodificar payload sin verificar)
cat jar.jwt | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Paso 2: Comprobar estado (deberia ser "pending")
curl -k -s "$BASE/status/$SESSION_ID" | python3 -m json.tool
# {"status": "pending"}

# Paso 3: POST direct_post (necesitas el VP JWT generado por el script)
curl -k -s -X POST "$BASE/direct_post" \
  -d "vp_token=<VP_JWT_AQUI>" \
  -d "state=<STATE_DEL_JAR>" \
  -d "presentation_submission={}"
# {"status": "ok"}

# Paso 4: Comprobar estado (deberia ser "completed")
curl -k -s "$BASE/status/$SESSION_ID" | python3 -m json.tool
# {"status": "completed"}
```

---

## 8. Tests unitarios con PHPUnit

### 8.1 Ejecutar los tests

```bash
cd /var/www/html/simplesamlphp/modules/oid4vp/

# Instalar dependencias de desarrollo
composer install --dev

# Ejecutar todos los tests
./vendor/bin/phpunit

# Ejecutar un test especifico
./vendor/bin/phpunit tests/Mapping/CredentialMapperTest.php
./vendor/bin/phpunit tests/Crypto/JwtHandlerTest.php
./vendor/bin/phpunit tests/Verification/PresentationVerifierTest.php
./vendor/bin/phpunit tests/Store/SessionStoreTest.php
```

### 8.2 Salida esperada

```
PHPUnit 10.x

Testing OID4VP Module Tests

...............                                  15 / 15 (100%)

Time: 00:00.045, Memory: 12.00 MB

OK (15 tests, 35 assertions)
```

### 8.3 Tests incluidos

| Fichero | Tests | Que verifica |
|---|---|---|
| `CredentialMapperTest` | 10 | Mapeo friendly/OID, array values, campos requeridos, overrides custom |
| `JwtHandlerTest` | 5 | Decodificacion JWT header, DID method no soportado, multibase invalido |
| `PresentationVerifierTest` | 5 | JWT invalido, algoritmo incorrecto, kid faltante, constructor |
| `SessionStoreTest` | 3 | Clase existe, constructor timeout, metodos publicos |

---

## 9. Verificar la SAML assertion resultante

Tras completar el flujo OID4VP, verificar que los atributos SAML son correctos.

### 9.1 Usando el test SP de SimpleSAMLphp

1. Acceder a `https://tu-idp/simplesaml/module.php/core/authenticate.php`
2. Seleccionar `multiauth`
3. Elegir "Presentar EducationalID"
4. Completar el flujo con la wallet simulada
5. La pagina mostrara los atributos recibidos

### 9.2 Atributos esperados (modo friendly name)

```
eduPersonPrincipalName     => ['jgarcia@universidad.es']
schacHomeOrganization      => ['universidad.es']
eduPersonScopedAffiliation => ['student@universidad.es']
eduPersonAffiliation       => ['student']
eduPersonAssurance         => ['https://refeds.org/assurance/IAP/low']
displayName                => ['Juan Garcia Lopez']
cn                         => ['Juan Garcia Lopez']
sn                         => ['Garcia Lopez']
givenName                  => ['Juan']
mail                       => ['jgarcia@universidad.es']
schacPersonalUniqueCode    => ['urn:schac:personalUniqueCode:int:esi:abc...']
uid                        => ['jgarcia']
eduPersonTargetedID        => ['<md5-del-did>']
```

### 9.3 Atributos esperados (modo OID, con `use_oid_format => true`)

```
urn:oid:1.3.6.1.4.1.5923.1.1.1.6    => ['jgarcia@universidad.es']     (ePPN)
urn:oid:1.3.6.1.4.1.25178.1.2.9     => ['universidad.es']             (schacHO)
urn:oid:1.3.6.1.4.1.5923.1.1.1.9    => ['student@universidad.es']     (ePSA)
urn:oid:1.3.6.1.4.1.5923.1.1.1.1    => ['student']                    (ePAff)
urn:oid:2.16.840.1.113730.3.1.241    => ['Juan Garcia Lopez']          (displayName)
urn:oid:2.5.4.3                      => ['Juan Garcia Lopez']          (cn)
urn:oid:2.5.4.4                      => ['Garcia Lopez']               (sn)
urn:oid:2.5.4.42                     => ['Juan']                       (givenName)
urn:oid:0.9.2342.19200300.100.1.3    => ['jgarcia@universidad.es']     (mail)
urn:oid:0.9.2342.19200300.100.1.1    => ['jgarcia']                    (uid)
```

### 9.4 Interaccion con authproc filters

Los authproc definidos en `saml20-idp-hosted.php` se ejecutan **despues** del mapeo OID4VP:

- **Filter 50 (name2oid)**: si `use_oid_format => false`, este filtro convierte los nombres amigables a OID. Si `use_oid_format => true`, los atributos ya estan en OID y el filtro no los modifica.
- **Filter 60 (eduPersonTargetedID)**: genera un targetedID basado en `mail`. Como OID4VP ya genera uno basado en el DID del credential subject, **habra dos valores** si `mail` existe. Puede ser deseable desactivar este filtro para sesiones OID4VP, o bien que el filtro compruebe si `eduPersonTargetedID` ya existe.
- **Filter 70 (ScopeAttribute)**: genera `eduPersonScopedAffiliation` desde `eduPersonAffiliation` + `schacHomeOrganization`. Si OID4VP ya proporciona `eduPersonScopedAffiliation`, el filtro lo sobrescribira. Considerar si esto es el comportamiento deseado.

---

## 10. Casos de error a probar

### 10.1 Sesion expirada

```bash
# Esperar mas de 5 minutos despues de generar el QR
# Luego intentar POST direct_post
curl -k -X POST "$BASE/direct_post" \
  -d "vp_token=xxx" -d "state=<state-expirado>"
# Esperado: 400 {"error":"invalid_request","error_description":"Unknown or expired state"}
```

### 10.2 Nonce incorrecto

Modificar el nonce en la VP JWT (usar un nonce diferente al del JAR):

```
# Esperado: 400 {"error":"invalid_presentation","error_description":"VP nonce mismatch"}
```

### 10.3 Tipo de VC incorrecto

Enviar una VP con un VC que no sea `VerifiableEducationalID`:

```
# Esperado: 400 {"error":"invalid_presentation","error_description":"VC does not contain required type: VerifiableEducationalID"}
```

### 10.4 Campos requeridos faltantes

Enviar un VC con `credentialSubject` que no tenga `eduPersonPrincipalName`, `schacHomeOrganization` o `displayName`:

```
# Esperado: 400 {"error":"invalid_presentation","error_description":"VC missing required fields: eduPersonPrincipalName, ..."}
```

### 10.5 Issuer no confiable (con trusted_issuers configurado)

Configurar `trusted_issuers => ['did:ebsi:zTrustedOnly']` y enviar un VC de un issuer diferente:

```
# Esperado: 400 {"error":"invalid_presentation","error_description":"VC issuer is not trusted: did:key:zTestIssuer123"}
```

### 10.6 Doble envio

Enviar el mismo VP dos veces a `/direct_post`:

```
# Primera vez: 200 {"status":"ok"}
# Segunda vez: 400 {"error":"invalid_request","error_description":"Session already processed"}
```

### 10.7 Polling despues de expiracion

```bash
# Tras 5 minutos
curl -k -s "$BASE/status/<session-id>"
# Esperado: 200 {"status":"expired"}
```

---

## 11. Diagnostico de problemas

### 11.1 Logs de SimpleSAMLphp

Los logs del modulo usan el prefijo `OID4VP:`:

```bash
# Ubicacion tipica
tail -f /var/log/simplesamlphp/simplesamlphp.log | grep OID4VP

# O si logging va a syslog
journalctl -f | grep OID4VP
```

Mensajes clave:

| Nivel | Mensaje | Significado |
|---|---|---|
| INFO | `VP verified successfully for session <uuid>` | Flujo exitoso |
| INFO | `Authentication completed successfully` | SAML assertion generada |
| WARNING | `VP verification failed: ...` | Error en verificacion de VP/VC |
| WARNING | `No trusted issuers or EBSI registry configured` | Modo desarrollo activo |
| ERROR | `Failed to load auth state: ...` | Cookie SSP expirada |

### 11.2 Problemas comunes

**"Signing key not found"**
```
Causa: La clave ES256 no esta en la ruta configurada, o certdir apunta a otro sitio.
Fix:   Verificar que cert/oid4vp.pem existe y es legible por el usuario del servidor web.
       ls -la /var/www/html/simplesamlphp/cert/oid4vp.pem
       El modulo busca primero la ruta tal cual y luego relativa a 'certdir'
       (resuelto respecto al directorio base de SSP, no al working directory).
```

**"Cannot create session directory"**
```
Causa: El directorio data/oid4vp_sessions/ no existe o no tiene permisos.
Fix:   mkdir -p data/oid4vp_sessions && chown www-data:www-data data/oid4vp_sessions
```

**Los ficheros de sesion aparecen en public/data/**
```
Causa: datadir apunta dentro del document root (ver seccion 6).
Fix:   Configurar 'datadir' en config/config.php a una ruta fuera de public/.
       Es un problema de seguridad: esos ficheros contienen los atributos
       de la credencial verificada.
```

**"cURL error 60: SSL certificate problem: unable to get local issuer certificate"**
```
Causa: api.blue.rediris.es envia solo su certificado hoja, sin el intermedio
       GEANT TLS RSA 1 que lo firma. Los navegadores lo descargan por AIA;
       curl no lo hace, asi que PHP no puede construir la cadena.
Fix:   Instalar el intermedio en el almacen de CAs del sistema:
       curl -sO http://crt.harica.gr/HARICA-GEANT-TLS-R1.cer
       openssl x509 -inform DER -in HARICA-GEANT-TLS-R1.cer \
         -out /usr/local/share/ca-certificates/harica-geant-tls-r1.crt
       update-ca-certificates
```

**"[BLUE] DID not found in any registry" / "[EBSI] DID not found..."**
```
Causa: El DID del emisor o del holder no esta publicado en el registro de esa red,
       o el IdP no tiene salida HTTPS hacia los registros.
Fix:   - Comprobar conectividad: curl -sI https://api.blue.rediris.es/did-registry/v5
       - Confirmar el entorno correcto (PROD/PRE/DES) con 'trust_networks'
       - Revisar el log: las lineas INFO indican que reintentos se hicieron
```

**"VC missing required fields: ..."**
```
Causa: La credencial no trae alguno de los campos exigidos. Por defecto se exigen
       solo los que el esquema EducationalID marca como obligatorios:
       id, identifier, eduPersonScopedAffiliation.
Fix:   El log incluye ademas los campos que SI trae la credencial ("present: ..."),
       lo que permite ver si el emisor usa otra nomenclatura.
       Si el despliegue necesita exigir mas atributos, declararlos en la opcion
       'required_attributes' del authsource. Exigir mas que el esquema hace que
       se rechacen credenciales validas.
```

**"VC issuer is not registered in the BLUE/EBSI Trusted Issuers Registry"**
```
Causa: El emisor resuelve correctamente pero no esta acreditado en el TIR de su red.
Fix:   - Verificar la acreditacion del emisor en el TIR correspondiente
       - En pruebas, anadir su DID a 'trusted_issuers' (se comprueba antes que el TIR)
```

**"VP JWT header missing kid" o fallo al resolver la clave del holder**
```
Causa: Habitualmente un did:key en formato EBSI (jwk_jcs-pub, multicodec 0xeb51),
       que versiones antiguas del modulo no sabian decodificar.
Fix:   Ya soportado. Si persiste, comprobar que el JWT usa ES256 y que el kid
       es un DID de un metodo soportado (ver seccion 4.4).
```

**"Failed to load ES256 private key"**
```
Causa: La clave no es EC P-256, o esta en formato incorrecto.
Fix:   openssl ec -in cert/oid4vp.pem -text -noout
       Debe mostrar "ASN1 OID: prime256v1"
```

**El QR no se genera (pagina en blanco o error JS)**
```
Causa: qrcode.min.js no cargado, o error en la configuracion Twig.
Fix:   Abrir consola del navegador (F12) y buscar errores JS.
       El script se sirve desde el propio modulo:
       /simplesaml/module.php/oid4vp/assets/qrcode.min.js
```

**Sale el boton "Abrir EUDI Wallet" en vez del QR en un escritorio**
```
Causa: Es intencionado si el viewport es < 480px o el dispositivo es tactil:
       no se puede escanear la pantalla que se esta sosteniendo.
Fix:   Ninguno. Ensanchar la ventana devuelve el QR.
```

**Los cambios en CSS/JS del modulo no se ven en el navegador**
```
Causa: SimpleSAMLphp cachea los assets con un parametro ?tag= que no cambia
       al sustituir los ficheros.
Fix:   Recarga forzada en el navegador (Cmd/Ctrl + Shift + R).
```

**La pagina QR desentona con la pantalla de login del tema**
```
Causa: Por defecto extiende 'base.twig' (layout generico de SimpleSAMLphp).
Fix:   Configurar 'template_base' apuntando al layout de login del tema.
       Para casos que necesiten mas envoltorio (tarjetas, rejillas), el tema
       puede sobreescribir la plantilla en themes/<Tema>/oid4vp/qrcode.twig.
```

**Polling nunca detecta "completed"**
```
Causa: La wallet no pudo hacer POST a /direct_post (CORS, firewall, etc.)
Fix:   - Verificar que /direct_post es accesible desde la red de la wallet
       - Revisar logs de Apache para 4xx/5xx en la ruta /direct_post
       - Asegurar HTTPS valido (las wallets rechazan certificados invalidos)
```

**"Authentication session expired" en direct_post**
```
Causa: La cookie de sesion SSP expiro antes de que la wallet respondiera.
Fix:   Aumentar session.cookie.lifetime en config/config.php de SSP.
       O reducir session_timeout del modulo OID4VP.
```

### 11.3 Verificar el estado del SessionStore

```bash
# Ver sesiones activas (file-based)
ls -la /var/www/html/simplesamlphp/data/oid4vp_sessions/

# Ver contenido de una sesion
cat /var/www/html/simplesamlphp/data/oid4vp_sessions/<uuid>.json | python3 -m json.tool

# Limpiar sesiones expiradas manualmente
find /var/www/html/simplesamlphp/data/oid4vp_sessions/ -name "*.json" -mmin +6 -delete
```

### 11.4 Verificar las rutas del modulo

```bash
# Las rutas deben estar en:
cat /var/www/html/simplesamlphp/modules/oid4vp/routing/routes.yaml

# Probar que los endpoints responden:
curl -k -s -o /dev/null -w "%{http_code}" "$BASE/qrpage"
# 400 (falta AuthState — es correcto, significa que la ruta funciona)

curl -k -s -o /dev/null -w "%{http_code}" "$BASE/status/nonexistent"
# 200 con {"status":"expired"} — correcto

curl -k -s -o /dev/null -w "%{http_code}" "$BASE/request_uri/nonexistent"
# 404 con {"error":"session_not_found"} — correcto
```
