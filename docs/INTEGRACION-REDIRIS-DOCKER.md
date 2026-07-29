# Integracion del modulo OID4VP en el IdP dockerizado de RedIRIS

Documento dirigido al equipo de RedIRIS que mantiene
[`rediris-es/idp_onprem_docker_ldap`](https://github.com/rediris-es/idp_onprem_docker_ldap).

Describe que hace falta para que el modulo `oid4vp` forme parte de la solucion
dockerizada, separando **lo que depende de RedIRIS** (imagen y tema) de **lo que ya
esta resuelto en el modulo**.

Todo lo que aparece aqui se ha verificado desplegando el `docker-compose.yaml` del
repositorio e instalando el modulo dentro del contenedor `sso_backend`.

## Indice

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Que aporta el modulo](#2-que-aporta-el-modulo)
3. [Entorno analizado](#3-entorno-analizado)
4. [Requisito 1: dependencias PHP en la imagen](#4-requisito-1-dependencias-php-en-la-imagen)
5. [Requisito 2: tematizacion de la pagina QR](#5-requisito-2-tematizacion-de-la-pagina-qr)
6. [Requisito 3: selector de multiauth](#6-requisito-3-selector-de-multiauth)
7. [Requisito 4: configuracion y variables de entorno](#7-requisito-4-configuracion-y-variables-de-entorno)
8. [Requisito 5: volumenes, claves y datos](#8-requisito-5-volumenes-claves-y-datos)
9. [Requisito 6: red saliente](#9-requisito-6-red-saliente)
10. [Notas sobre la actualizacion de SimpleSAMLphp](#10-notas-sobre-la-actualizacion-de-simplesamlphp)
11. [Checklist de integracion](#11-checklist-de-integracion)
12. [Como reproducir la prueba](#12-como-reproducir-la-prueba)

---

## 1. Resumen ejecutivo

El modulo funciona en la imagen actual de RedIRIS: se ha completado el flujo hasta
servir el JWT Authorization Request firmado a la wallet. Para integrarlo de forma
soportada quedan **dos acciones del lado de RedIRIS**:

| # | Accion | Responsable | Bloqueante |
|---|---|---|---|
| 1 | Anadir 3 librerias PHP a la imagen `backend-sso-ssp` | RedIRIS | **Si** |
| 2 | Anadir `'template_base' => 'baseSSO.twig'` a la config del authsource | RedIRIS | No (cosmetico) |
| 3 | Tematizar el selector de multiauth | RedIRIS | No (cosmetico) |
| 4 | Publicar plantilla propia en el tema para la tarjeta de login | RedIRIS | No (opcional) |

No se requiere ninguna extension PHP adicional: la dependencia de `ext-gmp` que tenia
el modulo se elimino precisamente porque la imagen no la incluye.

---

## 2. Que aporta el modulo

Una fuente de autenticacion (`oid4vp:OID4VP`) que permite al IdP autenticar usuarios
mediante **OpenID for Verifiable Presentations**: el usuario presenta una credencial
**EducationalID** desde su wallet EUDI escaneando un QR, y el modulo la verifica y la
convierte en atributos SAML (`eduPersonPrincipalName`, `mail`, `schacHomeOrganization`...).

Convive con el LDAP existente: se anade como una opcion mas dentro de `multiauth`, sin
tocar el flujo de usuario y contrasena.

Redes soportadas:

| Red | Metodo DID | Registros |
|---|---|---|
| **BLUE** (RedIRIS) | `did:blue` | PROD `api.blue.rediris.es`, con alternativas PRE y DES |
| **EBSI** | `did:ebsi` | Pilot `api-pilot.ebsi.eu`, espejo RedIRIS `api-pilot.ebsi.rediris.es`, Conformance |

El esquema EducationalID es identico en ambas redes (mismos campos de
`credentialSubject`), por lo que el mapeo a atributos SAML es comun.

---

## 3. Entorno analizado

Analisis realizado sobre las imagenes `:latest` en el momento de escribir este documento:

| Componente | Version / valor |
|---|---|
| `ghcr.io/.../backend-sso-ssp` | SimpleSAMLphp **2.3.3**, PHP **8.3.13** |
| `ghcr.io/.../frontend-sso-ssp` | nginx **1.27.1** |
| Tema activo | `themeRedIRIS:RedIRIS` (`theme.use` en `config/config.php`) |
| Modulos habilitados | adfs, admin, authorize, consent, consentAdmin, core, cron, discopower, exampleauth, ldap, metarefresh, multiauth, radius, saml, sqlauth, statistics, themeRedIRIS |
| Extensiones PHP | core, ctype, curl, date, dom, fileinfo, filter, hash, iconv, intl, json, ldap, libxml, mbstring, mysqli, mysqlnd, openssl, pcre, PDO, pdo_mysql, pdo_sqlite, Phar, posix, random, readline, Reflection, session, SimpleXML, soap, sodium, SPL, sqlite3, standard, tokenizer, xml, xmlreader, xmlwriter, Zend OPcache, zlib |

Dos observaciones relevantes:

- **No hay `gmp` ni `bcmath`** en la imagen. El modulo ya no las necesita.
- **No hay `composer` ni `git`** dentro del contenedor, asi que las dependencias PHP no
  pueden instalarse en tiempo de ejecucion: tienen que venir en la imagen.

---

## 4. Requisito 1: dependencias PHP en la imagen

**Es el unico punto bloqueante.**

El modulo necesita tres librerias que la imagen actual no incluye:

| Libreria | Version | Para que |
|---|---|---|
| `firebase/php-jwt` | ^6.0 \|\| ^7.0 | Firma y verificacion de JWT (ES256) |
| `guzzlehttp/guzzle` | ^7.0 | Consultas a los registros DID y TIR de EBSI/BLUE |
| `ramsey/uuid` | ^4.0 | Identificadores de sesion OID4VP |

Composer arrastra ademas sus dependencias transitivas (`psr/http-client`,
`psr/http-message`, `psr/http-factory`, `guzzlehttp/psr7`, `guzzlehttp/promises`,
`brick/math`, `ralouphie/getallheaders`).

### Opcion recomendada: instalar el modulo con composer al construir la imagen

Es la via natural, porque `composer-module-installer` de SimpleSAMLphp coloca el modulo
en `modules/oid4vp` y registra el autoload de todo de una sola vez:

```dockerfile
# En el Dockerfile de backend-sso-ssp, dentro del proyecto SimpleSAMLphp
WORKDIR /var/simplesamlphp
RUN composer require laarino/simplesamlphp-module-oid4vp --no-interaction --no-dev \
 && composer dump-autoload --optimize
```

`composer.json` del modulo ya declara `"type": "simplesamlphp-module"`, y el proyecto de
SimpleSAMLphp tiene habilitado `simplesamlphp/composer-module-installer` en
`allow-plugins`, por lo que no hace falta configuracion extra.

### Opcion alternativa: solo las librerias

Si se prefiere desplegar el modulo por volumen en lugar de por composer:

```dockerfile
WORKDIR /var/simplesamlphp
RUN composer require firebase/php-jwt guzzlehttp/guzzle ramsey/uuid \
      --no-interaction --no-dev \
 && composer dump-autoload --optimize
```

En este caso el modulo se monta como volumen y hay que registrar su namespace PSR-4
(`SimpleSAML\Module\oid4vp\` → `modules/oid4vp/src`) en el autoload del proyecto.

> **No recomendado**: parchear `vendor/` en caliente. Es lo que se hizo para la prueba
> descrita en la seccion 12 y funciona, pero se pierde en cada reconstruccion de la imagen.

### Verificacion

```bash
docker exec sso_backend php -r 'require "/var/simplesamlphp/vendor/autoload.php";
  var_dump(
    class_exists("Firebase\JWT\JWT"),
    class_exists("GuzzleHttp\Client"),
    class_exists("Ramsey\Uuid\Uuid"),
    class_exists("SimpleSAML\Module\oid4vp\Auth\Source\OID4VP")
  );'
```

Las cuatro deben devolver `true`.

---

## 5. Requisito 2: tematizacion de la pagina QR

El tema `themeRedIRIS` define dos layouts distintos:

| Layout | Uso actual | Aspecto |
|---|---|---|
| `themes/RedIRIS/default/base.twig` | Paginas genericas | Cabecera y pie RedIRIS sobre fondo plano |
| `themes/RedIRIS/default/baseSSO.twig` | `core/loginuserpass.twig` | Pantalla completa, carrusel de fondos y tarjeta centrada |

La pagina QR del modulo extiende `base.twig` por defecto. El resultado es correcto pero
**visualmente inconsistente**: el usuario ve la pantalla de login a pantalla completa y,
al elegir la wallet, una pagina con aspecto administrativo.

### Solucion minima (una linea)

En la configuracion del authsource:

```php
'oid4vp' => [
    'oid4vp:OID4VP',
    // ...
    'template_base' => 'baseSSO.twig',
],
```

Con esto la pagina QR adopta el layout de login de RedIRIS. Verificado en el despliegue.

### Solucion completa (tarjeta con fondo)

`baseSSO.twig` espera que el contenido aporte el envoltorio de columnas, la tarjeta y el
`div#imageContainer` sobre el que actua el carrusel (`RedIRIS_slider.js`). Ese marcado es
propio del tema, no del modulo, asi que la via correcta es el **mecanismo estandar de
sobreescritura de plantillas de SimpleSAMLphp**: publicar en el repositorio del tema

```
themes/RedIRIS/oid4vp/qrcode.twig
```

Esa plantilla tiene prioridad sobre la del modulo sin que haya que tocar el modulo. Como
punto de partida (probado y con el resultado esperado):

```twig
{% set pagetitle = 'Scan the QR code with your wallet' | trans %}
{% extends "baseSSO.twig" %}

{% block preload %}
    <link rel="stylesheet" href="{{ asset('oid4vp.css', 'oid4vp') }}">
{% endblock %}

{% block content %}
<div id="imageContainer" class="col-md-6 col-xl-8 image-container"></div>

<div class="col-md-6 col-xl-4 d-flex justify-content-center align-items-center vh-100">
  <div class="card border border-light-subtle rounded-3 shadow-sm opacity-card-body mx-5">
    <div class="card-body">

      <div class="text-center pb-3 pt-2">
        <img src="{{ asset('images/logo/'~ logo, 'themeRedIRIS') }}"
             alt="SSO Logo" class="img-fluid img-card w-100">
      </div>

      {# --- contenido del modulo: copiar el bloque content de --- #}
      {# --- modules/oid4vp/templates/qrcode.twig tal cual      --- #}

    </div>
  </div>
</div>
{% endblock %}
```

Notas para quien la mantenga:

- `logo` y `fondos` los inyecta `RedIRISController::display()`, asi que estan disponibles
  igual que en `loginuserpass.twig`.
- El `div#oid4vp-app` y sus atributos `data-*` **deben conservarse intactos**: de ahi lee
  toda su configuracion el JavaScript del modulo.
- El CSS del modulo no impone colores de texto: hereda del tema (`color: inherit`). Solo
  la tarjeta del QR mantiene fondo blanco, porque el codigo necesita su zona de silencio
  para ser escaneable.

### Comportamiento responsive

No hay que hacer nada: en dispositivos tactiles o con viewport menor de 480 px, el modulo
oculta el QR y muestra un boton de deep-link (`openid://`), cambiando tambien el titular y
las instrucciones. Escanear la pantalla que se sostiene no es posible.

---

## 6. Requisito 3: selector de multiauth

El selector (`multiauth:MultiAuth`) es la pantalla desde la que el usuario elige entre
LDAP y wallet, es decir, **la puerta de entrada al flujo OID4VP**. Actualmente el tema no
lo sobreescribe: se renderiza con `base.twig` y botones grises por defecto, con un salto
visual notable respecto a la pantalla de login.

No es un problema del modulo, pero afecta a la experiencia de la funcionalidad que
aportamos. La solucion es la misma via estandar:

```
themes/RedIRIS/multiauth/selectsource.twig
```

Recomendable resolverlo a la vez que la plantilla del QR, para que las tres pantallas
(seleccion → QR → resultado) tengan un aspecto continuo.

---

## 7. Requisito 4: configuracion y variables de entorno

### 7.1 authsources.php

El modulo se anade como una fuente mas y se ofrece dentro de `multiauth`:

```php
'oid4vp' => [
    'oid4vp:OID4VP',

    // Entity ID del IdP. Se usa como 'iss' del JAR y se valida como 'aud' del VP.
    'verifier_id' => 'https://idp.institucion.es',

    // Claves ES256, independientes de las de firma SAML
    'signing_key'  => 'oid4vp.pem',
    'signing_cert' => 'oid4vp.crt',

    'session_timeout' => 300,
    'use_oid_format'  => false,

    // Emisores siempre confiables (se comprueba antes que cualquier registro)
    'trusted_issuers' => [],

    // Layout del tema para la pagina QR
    'template_base' => 'baseSSO.twig',
],

'multi' => [
    'multiauth:MultiAuth',
    'sources' => [
        'auth-ldap' => [
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
```

Y en `saml20-idp-hosted.php`, `'auth' => 'multi'`.

### 7.2 Variables de entorno sugeridas

Siguiendo el patron de `config_files/config_back.env`, estas son las variables que
tendria sentido exponer para no obligar a editar ficheros PHP:

```bash
### Configuracion OID4VP (presentacion de credenciales verificables)

# Activar la opcion de wallet en el selector de login
OID4VP_ENABLED = "false"

# Entity ID del verificador. Si se deja vacio se usa DOMAIN_SSO
OID4VP_VERIFIER_ID = ""

# Nombres de los ficheros de clave ES256 dentro de cert/
OID4VP_SIGNING_KEY  = "oid4vp.pem"
OID4VP_SIGNING_CERT = "oid4vp.crt"

# Caducidad del QR en segundos
OID4VP_SESSION_TIMEOUT = "300"

# Emisores siempre confiables, separados por comas.
# Vacio = solo se confia en los registrados en el TIR de su red (EBSI/BLUE).
OID4VP_TRUSTED_ISSUERS = ""

# Entorno de la red BLUE: PROD (por defecto) | PRE | DES
OID4VP_BLUE_ENV = "PROD"

# Layout del tema para la pagina QR
OID4VP_TEMPLATE_BASE = "baseSSO.twig"
```

`OID4VP_BLUE_ENV` se traduce a una entrada de `trust_networks`; los valores concretos de
cada entorno estan en `config/module_oid4vp.php` y en la
[guia de habilitacion](GUIA-HABILITACION-Y-TESTING.md).

### 7.3 Semantica de confianza (importante)

Conviene tenerla presente al documentar de cara a las instituciones:

1. DID incluido en `trusted_issuers` → **aceptado** siempre.
2. DID de una red conocida (`did:ebsi`, `did:blue`) → se consulta el TIR de esa red.
   Si no esta acreditado, **se rechaza**.
3. DID sin red (`did:key`, `did:jwk`, `did:web`) → si no hay `trusted_issuers` ni
   `ebsi_trust_registry`, se acepta dejando un WARNING en el log. Es **modo desarrollo**:
   en produccion debe configurarse siempre una fuente de confianza.

---

## 8. Requisito 5: volumenes, claves y datos

### 8.1 Claves ES256

Son **independientes** de las claves RSA de firma SAML y hay que generarlas aparte. Encaja
de forma natural en `init_script.sh`, junto a la generacion de certificados actual:

```bash
CERT_DIR="./config_files/simpleSAMLphp/certificados_firma"

if [ ! -f "${CERT_DIR}/oid4vp.pem" ]; then
  echo "Generando claves ES256 para OID4VP..."
  openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/oid4vp.pem"
  openssl ec -in "${CERT_DIR}/oid4vp.pem" -pubout -out "${CERT_DIR}/oid4vp.crt"
  chmod 600 "${CERT_DIR}/oid4vp.pem"
  chmod 644 "${CERT_DIR}/oid4vp.crt"
  chown 33:33 "${CERT_DIR}/oid4vp.pem" "${CERT_DIR}/oid4vp.crt"
fi
```

El volumen que ya existe en `docker-compose.yaml` las publica sin cambios:

```yaml
- ./config_files/simpleSAMLphp/certificados_firma:/var/simplesamlphp/cert/
```

### 8.2 Directorios de datos

| Directorio | Contenido | Persistencia |
|---|---|---|
| `data/oid4vp_sessions/` | Sesiones OID4VP: nonce, state, config del verificador y, tras verificar, los atributos de la credencial | Efimero (TTL corto) |
| `data/oid4vp_cache/` | Documentos DID y respuestas del TIR, 48 h | Conviene persistir |

Si `store.type` es `sql` en `config/config.php`, las sesiones van a base de datos y solo
queda la cache en disco. Persistir la cache entre reinicios reduce las consultas a los
registros de EBSI/BLUE:

```yaml
volumes:
  - ./data/oid4vp_cache:/var/simplesamlphp/data/oid4vp_cache
```

### 8.3 Aviso de seguridad sobre `datadir`

`datadir` **debe apuntar fuera del document root**. Los ficheros de sesion contienen los
atributos de la credencial ya verificada.

En la imagen actual, `config/config.php` trae `'datadir' => 'data/'` (ruta relativa). Como
el working directory de php-fpm es `public/`, cualquier codigo que resuelva esa ruta con
`getOptionalString()` acaba escribiendo en `/var/simplesamlphp/public/data/`, es decir,
dentro del arbol servido. **El modulo ya lo resuelve correctamente** usando
`Configuration::getPathValue()`, que interpreta la ruta respecto al directorio base de
SimpleSAMLphp.

En el despliegue actual esos ficheros no llegaban a servirse porque nginx corre en otro
contenedor y no tiene montado `/var/simplesamlphp/public`. Aun asi, merece la pena revisar
si otros modulos comparten el patron, y comprobarlo tras un flujo de prueba:

```bash
docker exec sso_backend ls /var/simplesamlphp/public/data 2>/dev/null \
  && echo "PROBLEMA: hay datos dentro del document root"
```

---

## 9. Requisito 6: red saliente

El contenedor `sso_backend` necesita salida HTTPS hacia los registros de las redes de
confianza. Con cortafuegos o proxy de salida hay que permitir:

| Red | Destinos |
|---|---|
| BLUE | `api.blue.rediris.es`, `api-pre.blue.rediris.es`, `api-des.blue.rediris.es` |
| EBSI | `api-pilot.ebsi.eu`, `api-pilot.ebsi.rediris.es`, `api-conformance.ebsi.eu` |

Ademas, el endpoint `/direct_post` **debe ser accesible desde la red de la wallet** (red
movil del usuario, normalmente Internet publico) y servirse por **HTTPS con certificado
valido**: las wallets EUDI rechazan certificados no confiables. Esto encaja con el
`ProxyPass` de Apache/nginx ya documentado en el README del repositorio.

Rutas publicadas por el modulo:

| Metodo | Ruta | Quien la llama |
|---|---|---|
| GET | `/simplesaml/module.php/oid4vp/qrpage` | Navegador |
| GET | `/simplesaml/module.php/oid4vp/request_uri/{id}` | Wallet |
| POST | `/simplesaml/module.php/oid4vp/direct_post` | Wallet |
| GET | `/simplesaml/module.php/oid4vp/status/{id}` | Navegador (polling cada 2 s) |

No requieren reglas especiales en nginx: entran por el `location ^~ /simplesaml` existente.

---

## 10. Notas sobre la actualizacion de SimpleSAMLphp

RedIRIS ha comentado la intencion de actualizar componentes. Sobre el modulo:

- Es compatible con **SimpleSAMLphp >= 2.0** y esta probado sobre **2.3.3**. No usa APIs
  marcadas como obsoletas en la rama 2.x.
- Depende del modulo `multiauth` solo para el enlace "volver a opciones de login", y de
  forma defensiva: si no se llego por multiauth, el enlace simplemente no se muestra.
- Requiere PHP >= 8.0 y funciona sobre PHP 8.3. Sin extensiones mas alla de `openssl`.

Si la actualizacion incluye un cambio del tema, conviene aprovechar para incorporar las
plantillas de las secciones 5 y 6.

---

## 11. Checklist de integracion

**Imagen `backend-sso-ssp`**

- [ ] Anadir `firebase/php-jwt`, `guzzlehttp/guzzle` y `ramsey/uuid` (o instalar el modulo
      completo con `composer require laarino/simplesamlphp-module-oid4vp`)
- [ ] Verificar que las cuatro clases de la seccion 4 cargan
- [ ] Confirmar que `oid4vp` aparece habilitado (el modulo trae `default-enable`)

**Tema `themeRedIRIS`**

- [ ] Publicar `themes/RedIRIS/oid4vp/qrcode.twig` (seccion 5)
- [ ] Publicar `themes/RedIRIS/multiauth/selectsource.twig` (seccion 6)

**Repositorio `idp_onprem_docker_ldap`**

- [ ] Generar claves ES256 en `init_script.sh`
- [ ] Anadir las variables `OID4VP_*` a `config_files/config_back.env`
- [ ] Plantillas de `authsources.php` y `saml20-idp-hosted.php` con la fuente y multiauth
- [ ] Volumen para `data/oid4vp_cache`
- [ ] Documentar los destinos de red saliente

**Verificacion**

- [ ] El selector muestra la opcion de wallet
- [ ] La pagina QR se ve integrada con el tema
- [ ] `/request_uri/{id}` devuelve 200 con `Content-Type: application/oauth-authz-req+jwt`
- [ ] Flujo completo con una wallet real contra BLUE (PRE o DES)
- [ ] La asercion SAML incluye los atributos esperados
- [ ] No hay ficheros en `public/data/`

---

## 12. Como reproducir la prueba

Pasos seguidos para el analisis, por si se quiere repetir:

```bash
git clone https://github.com/rediris-es/idp_onprem_docker_ldap.git
cd idp_onprem_docker_ldap

# 1. Rellenar config_files/config_back.env y config_front.env
#    (para una prueba local basta con valores ficticios; el LDAP no hace falta
#     si solo se va a probar el flujo OID4VP)

# 2. Generar certificados de firma y levantar
sh init_script.sh 'PRUEBA' 'ES' 'Madrid' 'Madrid' 'PRUEBA' 'TI' 'localhost' 'admin@example.org'

# 3. Instalar el modulo en el contenedor
docker cp <ruta-al-modulo> sso_backend:/var/simplesamlphp/modules/oid4vp
docker exec -u root sso_backend chown -R www-data:www-data /var/simplesamlphp/modules/oid4vp

# 4. Instalar las dependencias PHP (ver seccion 4)

# 5. Generar las claves ES256
docker exec -u root sso_backend sh -c '
  cd /var/simplesamlphp/cert &&
  openssl ecparam -name prime256v1 -genkey -noout -out oid4vp.pem &&
  openssl ec -in oid4vp.pem -pubout -out oid4vp.crt &&
  chown www-data:www-data oid4vp.pem oid4vp.crt && chmod 600 oid4vp.pem'

# 6. Anadir el authsource y habilitar el modulo en config.php, y reiniciar
docker compose restart sso-fpm
```

Acceso: `http://localhost:8052/simplesaml/module.php/admin/test/multi`, con la contrasena
de `PASSW_SSPHP`.

Dos ajustes **solo validos para pruebas locales sin TLS** (no aplicar en despliegues
reales), porque en HTTP el navegador rechaza la cookie de sesion:

```bash
docker exec -u root sso_backend sed -i \
  "s/'session.cookie.secure' => true/'session.cookie.secure' => false/" \
  /var/simplesamlphp/config/config.php

docker exec -u root sso_backend sed -i \
  "s/'session.cookie.samesite' => .*/'session.cookie.samesite' => 'Lax',/" \
  /var/simplesamlphp/config/config.php
```

Un detalle que despista al iterar sobre el tema: SimpleSAMLphp cachea CSS y JS con un
parametro `?tag=` que no cambia al sustituir los ficheros. Hay que forzar la recarga en el
navegador (`Cmd/Ctrl + Shift + R`) para ver los cambios.

---

## Contacto

Modulo mantenido en el marco del proyecto DC4EU / red BLUE.
Licencia EUPL-1.2. Ver [README](../README.md) y
[guia de habilitacion y testing](GUIA-HABILITACION-Y-TESTING.md).
