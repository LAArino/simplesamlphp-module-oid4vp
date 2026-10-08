# Integracion del modulo OID4VP en el IdP dockerizado de RedIRIS

Este documento es un **resumen**. El despliegue completo —ficheros, variables, plantillas
y diagnostico— vive en el repositorio donde se usa:

**→ [`rediris-es/idp_onprem_blue`](https://github.com/rediris-es/idp_onprem_blue)**, y en
particular su [`docs/INTEGRACION-OID4VP.md`](https://github.com/rediris-es/idp_onprem_blue/blob/main/docs/INTEGRACION-OID4VP.md)
(repositorio privado de RedIRIS: los enlaces solo abren con acceso concedido).

Se mantiene aqui solo lo que necesita saber alguien que llegue al modulo y quiera entender
como encaja en la solucion de RedIRIS. El detalle operativo esta deliberadamente en un
unico sitio: cuando estuvo duplicado, las dos copias divergieron.

---

## Que aporta el modulo

Una fuente de autenticacion (`oid4vp:OID4VP`) que permite al IdP autenticar usuarios
mediante **OpenID for Verifiable Presentations**: el usuario presenta una credencial
**EducationalID** desde su wallet EUDI escaneando un QR, y el modulo la verifica y la
convierte en atributos SAML (`eduPersonPrincipalName`, `mail`, `schacHomeOrganization`...).

Convive con el LDAP existente: se anade como una opcion mas dentro de `multiauth`, sin
tocar el flujo de usuario y contrasena.

| Red | Metodo DID | Credencial | Registros |
|---|---|---|---|
| **BLUE** (RedIRIS) | `did:blue` | `VerifiableEducationalID` | PROD, con reintento en PRE y DES |
| **EBSI** | `did:ebsi` | `EducationalId` | Pilot, espejo RedIRIS y Conformance |

El esquema EducationalID es identico en ambas redes, por lo que el mapeo a atributos SAML
es comun. Para cada credencial se resuelve el DID del emisor en el registro de su red y se
comprueba que este acreditado en el **Trusted Issuers Registry** correspondiente; un emisor
no acreditado se rechaza.

---

## Estado

Verificado de extremo a extremo sobre el contenedor de RedIRIS, con una wallet EUDI real y
credenciales autenticas de las dos redes: en ambos casos se emitio la asercion SAML con los
atributos mapeados.

---

## Que necesita de la imagen `backend-sso-ssp`

Tres cosas que la imagen publicada no trae. Las tres las resuelve el `Dockerfile` de
`idp_onprem_blue`; se listan aqui porque, si RedIRIS las incorporase a la imagen oficial,
ese `Dockerfile` se simplificaria o desapareceria.

| Falta | Detalle |
|---|---|
| **composer** | No esta en la imagen, asi que las dependencias no se pueden instalar en caliente. Se toma del binario oficial en una etapa previa |
| **Librerias PHP** | `firebase/php-jwt`, `guzzlehttp/guzzle` y `ramsey/uuid` |
| **`'oid4vp'` en `module.enable`** | `config.php` enumera los modulos y esa lista vence sobre el `default-enable` del modulo |

El modulo **no** requiere `ext-gmp` ni `ext-bcmath`: implementa base58 internamente
precisamente porque la imagen no incluye ninguna de las dos.

Instalacion, con el paquete publicado en Packagist:

```dockerfile
WORKDIR /var/simplesamlphp
RUN composer require laarino/simplesamlphp-module-oid4vp:^1.0 \
        --no-interaction --update-no-dev --no-progress \
 && composer dump-autoload --optimize --no-dev
```

`composer.json` del modulo declara `"type": "simplesamlphp-module"`, y el proyecto de
SimpleSAMLphp tiene habilitado `composer-module-installer`, asi que el modulo acaba en
`modules/oid4vp` con su autoload registrado sin configuracion extra.

---

## Punto abierto del lado de RedIRIS

**Proxy interno en la imagen publicada.** `backend-sso-ssp` trae fijado en su entorno:

```
http_proxy=http://130.206.1.58:51080
https_proxy=http://130.206.1.58:51080
```

Esa direccion solo es alcanzable desde la red de RedIRIS. Fuera de ella rompe la
construccion y, en ejecucion, **las consultas a los registros DID y TIR**: Guzzle respeta
esas variables, asi que toda la verificacion de credenciales saldria por un proxy
inalcanzable.

`idp_onprem_blue` lo neutraliza por defecto y lo deja como argumento de construccion, pero
conviene revisar si debe venir en una imagen pensada para desplegarse en otras
instituciones, porque afecta a todo el producto y no solo a OID4VP.

> La **cadena TLS de `api.blue.rediris.es`** estuvo en esta lista hasta octubre de 2026.
> RedIRIS la corrigio en origen —certificado ECC y cadena completa— y ya no hace falta
> ningun parche: comprobado en PROD, PRE y DES.

---

## Tematizacion

La pagina QR se dibuja dentro del tema del despliegue. Con `template_base` apuntando al
layout de login del tema (`baseSSO.twig` en el de RedIRIS) adopta su aspecto; para la
tarjeta con carrusel de fondos, el tema puede sobreescribir la plantilla publicando
`themes/RedIRIS/oid4vp/qrcode.twig`, que es el mecanismo estandar de SimpleSAMLphp.

`idp_onprem_blue` ya incluye esa plantilla lista para montar.

> **Pendiente en el repositorio del tema:** el selector de `multiauth` no esta tematizado y
> se renderiza con botones genericos. Es la pantalla desde la que se entra al flujo OID4VP,
> asi que conviene resolverlo publicando `themes/RedIRIS/multiauth/selectsource.twig`.

---

## Donde seguir

| Para | Ver |
|---|---|
| Desplegar el IdP con OID4VP | [`rediris-es/idp_onprem_blue`](https://github.com/rediris-es/idp_onprem_blue) |
| Cada decision de integracion y su diagnostico | [`docs/INTEGRACION-OID4VP.md`](https://github.com/rediris-es/idp_onprem_blue/blob/main/docs/INTEGRACION-OID4VP.md) del mismo repositorio |
| Instalar el modulo fuera de ese despliegue | [Guia de habilitacion y testing](GUIA-HABILITACION-Y-TESTING.md) · [English](SETUP-AND-TESTING.md) |
| Todas las opciones de configuracion | [`config/module_oid4vp.php`](../config/module_oid4vp.php) |

Modulo mantenido en el marco del proyecto DC4EU / red BLUE. Licencia EUPL-1.2.
