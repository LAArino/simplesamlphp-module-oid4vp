# Guia de habilitacion y testing del modulo OID4VP

## Indice

1. [Requisitos previos](#1-requisitos-previos)
2. [Generar claves ES256 para el verificador](#2-generar-claves-es256-para-el-verificador)
3. [Instalar dependencias PHP](#3-instalar-dependencias-php)
4. [Configurar SimpleSAMLphp](#4-configurar-simplesamlphp)
5. [Verificar que el modulo esta habilitado](#5-verificar-que-el-modulo-esta-habilitado)
6. [Crear directorio de sesiones](#6-crear-directorio-de-sesiones)
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
| ext-gmp | * | `php -m \| grep gmp` |
| ext-json | * | `php -m \| grep json` |
| SimpleSAMLphp | 2.0+ | Ver `config/config.php` |
| Composer | 2.x | `composer --version` |
| curl | * | `curl --version` |
| openssl CLI | * | `openssl version` |

### Instalar ext-gmp si falta

```bash
# Debian/Ubuntu
sudo apt install php-gmp
sudo systemctl restart apache2

# RHEL/CentOS
sudo dnf install php-gmp
sudo systemctl restart httpd

# Verificar
php -m | grep gmp
```

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

        // Issuers de confianza (en produccion, anadir DIDs reales)
        'trusted_issuers' => [
            // 'did:ebsi:z...',
        ],

        // null = modo desarrollo (acepta cualquier issuer con warning)
        'ebsi_trust_registry' => null,
    ],
];
```

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

## 6. Crear directorio de sesiones

El SessionStore usa almacenamiento basado en ficheros. El directorio debe existir y ser escribible por Apache:

```bash
# Crear el directorio
mkdir -p /var/www/html/simplesamlphp/data/oid4vp_sessions

# Permisos: solo Apache puede leer/escribir
chown www-data:www-data /var/www/html/simplesamlphp/data/oid4vp_sessions
chmod 700 /var/www/html/simplesamlphp/data/oid4vp_sessions
```

> **Nota**: Si SimpleSAMLphp tiene configurado `store.type => 'sql'` en `config/config.php`, el modulo usara automaticamente la base de datos SQL en lugar de ficheros. No se necesita crear el directorio en ese caso.

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
Causa: La clave ES256 no esta en la ruta configurada.
Fix:   Verificar que cert/oid4vp.pem existe y es legible por Apache.
       ls -la /var/www/html/simplesamlphp/cert/oid4vp.pem
```

**"Cannot create session directory"**
```
Causa: El directorio data/oid4vp_sessions/ no existe o no tiene permisos.
Fix:   mkdir -p data/oid4vp_sessions && chown www-data:www-data data/oid4vp_sessions
```

**"Failed to load ES256 private key"**
```
Causa: La clave no es EC P-256, o esta en formato incorrecto.
Fix:   openssl ec -in cert/oid4vp.pem -text -noout
       Debe mostrar "ASN1 OID: prime256v1"
```

**El QR no se genera (pagina en blanco o error JS)**
```
Causa: CDN de qrcode.js no accesible, o error en la configuracion Twig.
Fix:   Abrir consola del navegador (F12) y buscar errores JS.
       Verificar que la URL del CDN es accesible.
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
