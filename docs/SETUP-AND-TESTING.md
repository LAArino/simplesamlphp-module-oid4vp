# OID4VP module: setup and testing guide

> **Languages** — English (this document) · [Castellano](GUIA-HABILITACION-Y-TESTING.md)
>
> This English version is normative. When you change one, change the other.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Generate the verifier's ES256 keys](#2-generate-the-verifiers-es256-keys)
3. [Install the PHP dependencies](#3-install-the-php-dependencies)
4. [Configure SimpleSAMLphp](#4-configure-simplesamlphp)
5. [Check that the module is enabled](#5-check-that-the-module-is-enabled)
6. [Create the data directories](#6-create-the-data-directories)
7. [Manual test: the full flow with a simulated wallet](#7-manual-test-the-full-flow-with-a-simulated-wallet)
8. [Unit tests with PHPUnit](#8-unit-tests-with-phpunit)
9. [Check the resulting SAML assertion](#9-check-the-resulting-saml-assertion)
10. [Error cases worth testing](#10-error-cases-worth-testing)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

### Software

| Requirement | Minimum version | Check with |
|---|---|---|
| PHP | 8.0+ | `php -v` |
| ext-openssl | * | `php -m \| grep openssl` |
| ext-json | * | `php -m \| grep json` |
| SimpleSAMLphp | 2.0+ | See `config/config.php` |
| Composer | 2.x | `composer --version` |
| curl | * | `curl --version` |
| openssl CLI | * | `openssl version` |

> **About `ext-gmp`**: earlier versions of the module required it to decode base58
> (`did:key` resolution). It is no longer needed: the module implements base58 itself
> without any arbitrary-precision library, so it installs on PHP images that ship
> neither `gmp` nor `bcmath`.

### Outbound connectivity

Verifying credentials from the EBSI and BLUE networks requires outbound HTTPS from the
IdP to each network's registries. Behind a firewall or an outbound proxy, allow these
destinations:

| Network | Destinations |
|---|---|
| EBSI | `api-pilot.ebsi.eu`, `api-pilot.ebsi.rediris.es` (mirror), `api-conformance.ebsi.eu` |
| BLUE | `api.blue.rediris.es`, `api-pre.blue.rediris.es`, `api-des.blue.rediris.es` |

Without this connectivity, only issuers resolved locally (`did:key`, `did:jwk`) and those
listed in the static `trusted_issuers` option will work.

---

## 2. Generate the verifier's ES256 keys

The ES256 keys (P-256/prime256v1) are **separate** from the IdP's RSA SAML keys. They are
used solely to sign the JWT Authorization Requests (JAR) of the OID4VP protocol.

```bash
# Move into SimpleSAMLphp's cert/ directory
cd /var/www/html/simplesamlphp/cert/

# Generate the EC P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out oid4vp.pem

# Extract the public key
openssl ec -in oid4vp.pem -pubout -out oid4vp.crt

# Restrictive permissions (readable only by the web server user)
chmod 600 oid4vp.pem
chown www-data:www-data oid4vp.pem oid4vp.crt

# Confirm the key really is P-256
openssl ec -in oid4vp.pem -text -noout 2>&1 | head -1
# Should print: ASN1 OID: prime256v1
```

### Generate a test key pair too (to simulate the wallet and the issuer)

```bash
# Test "issuer" key (whoever issued the EducationalID)
openssl ecparam -name prime256v1 -genkey -noout -out test_issuer.pem
openssl ec -in test_issuer.pem -pubout -out test_issuer_pub.pem

# Test "holder" key (the user's wallet)
openssl ecparam -name prime256v1 -genkey -noout -out test_holder.pem
openssl ec -in test_holder.pem -pubout -out test_holder_pub.pem
```

---

## 3. Install the PHP dependencies

```bash
cd /var/www/html/simplesamlphp/modules/oid4vp/
composer install

# Check they were installed
composer show firebase/php-jwt
composer show guzzlehttp/guzzle
composer show ramsey/uuid
```

If the module is managed as part of the main SimpleSAMLphp project, install it from the
project root instead:

```bash
cd /var/www/html/simplesamlphp/
composer require laarino/simplesamlphp-module-oid4vp
```

---

## 4. Configure SimpleSAMLphp

### 4.1 authsources.php

Edit `/var/www/html/simplesamlphp/config/authsources.php`:

```php
$config = [

    'admin' => ['core:AdminPassword'],

    // MultiAuth: offers both login options
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

    // Your existing LDAP auth source
    'ldap' => [
        'ldap:LDAP',
        // ... your existing LDAP configuration ...
    ],

    // OID4VP auth source (new)
    'oid4vp' => [
        'oid4vp:OID4VP',

        // CHANGE this to your real entity ID
        'verifier_id' => 'https://idp.your-university.org',

        // ES256 keys (generated in step 2)
        'signing_cert' => 'cert/oid4vp.crt',
        'signing_key'  => 'cert/oid4vp.pem',

        // QR timeout (5 minutes)
        'session_timeout' => 300,

        // false = friendly names (cn, sn, mail...)
        // true  = OID format (urn:oid:2.5.4.3, ...)
        'use_oid_format' => false,

        // Static list of trusted issuers. ALWAYS checked first, before any
        // network registry.
        'trusted_issuers' => [
            // 'did:ebsi:z...',
            // 'did:blue:z...',
        ],

        // Trust networks. EBSI (did:ebsi) and BLUE (did:blue) are built in with
        // their default registries; fill this in only to override a network or
        // add a new one. See section 4.3.
        'trust_networks' => [],

        // Fields a presentation must carry. Defaults to the ones the EducationalID
        // schema marks as required (id, identifier, eduPersonScopedAffiliation).
        // Demanding more rejects credentials that are perfectly valid.
        // 'required_attributes' => ['id', 'identifier', 'eduPersonScopedAffiliation'],

        // Layout the QR page extends. Point it at your own theme's login layout so
        // the QR screen does not clash with the username and password one.
        'template_base' => 'base.twig',
    ],
];
```

### 4.2 saml20-idp-hosted.php

Check that the IdP uses MultiAuth:

```php
$metadata['__DYNAMIC:1__'] = [
    'host' => '__DEFAULT__',
    'auth' => 'multiauth',      // <-- must point to 'multiauth'
    'privatekey'  => 'idp.pem',
    'certificate' => 'idp.crt',
    // ... rest of the configuration ...
];
```

### 4.3 Trust networks (EBSI and BLUE)

The module picks the registry from the issuer DID's method, with retry chains mirroring
the wallet's own:

| DID method | Network | Primary | Fallback (network error) | Alternates (404) |
|---|---|---|---|---|
| `did:ebsi` | EBSI | `api-pilot.ebsi.eu` | `api-pilot.ebsi.rediris.es` | `api-conformance.ebsi.eu` |
| `did:blue` | BLUE | `api.blue.rediris.es` | — | `api-pre...`, `api-des...` |

Each network provides a DID Registry and a Trusted Issuers Registry (TIR). Successful
lookups are cached on disk for 48 hours.

**Trust semantics**, in order:

1. DID listed in `trusted_issuers` → accepted.
2. DID of a known network (`did:ebsi`, `did:blue`) → its TIR is queried. **If the issuer
   is not registered there, it is rejected.**
3. DID with no associated network (`did:key`, `did:jwk`, `did:web`) → if neither
   `trusted_issuers` nor `ebsi_trust_registry` is configured, it is accepted with a
   WARNING in the log (**development mode: do not rely on this in production**).

To pin a specific environment, override that network's entry:

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
        'alternate_configs' => [],   // no retry chain
    ],
],
```

### 4.4 Supported DID methods

| Method | Resolution |
|---|---|
| `did:key` | Local. Multicodec `0x1200` (compressed P-256) and `0xeb51` (`jwk_jcs-pub`, the EBSI format) |
| `did:jwk` | Local (JWK embedded in the DID) |
| `did:web` | Over HTTPS per the W3C specification, checking that the document's `id` matches |
| `did:ebsi`, `did:blue` | Their network's DID Registry |
| Anything else | Universal Resolver (`dev.uniresolver.io`) — **development only** |

---

## 5. Check that the module is enabled

The `modules/oid4vp/default-enable` file marks the module as enabled by default. Check it:

```bash
# The file must exist
ls -la /var/www/html/simplesamlphp/modules/oid4vp/default-enable

# Check in SimpleSAMLphp's admin UI:
# https://your-idp/simplesaml/module.php/core/frontpage_welcome.php
# -> "Configuration" tab -> "Modules" -> oid4vp should appear as enabled
```

If it does not show up as enabled, create the file:

```bash
touch /var/www/html/simplesamlphp/modules/oid4vp/default-enable
```

> **Careful**: if `config.php` enumerates modules in `module.enable`, that list wins over
> `default-enable` and the module stays disabled, with auth sources failing with
> "The module 'oid4vp' is not enabled". In that case add `'oid4vp' => true` to the list.

---

## 6. Create the data directories

The module uses two directories under SimpleSAMLphp's `datadir`:

| Directory | Contents |
|---|---|
| `data/oid4vp_sessions/` | OID4VP sessions: nonce, state, verifier configuration and, once verified, the credential's attributes |
| `data/oid4vp_cache/` | Cache of DID documents and TIR lookups (48 h TTL) |

```bash
# Create the directories
mkdir -p /var/www/html/simplesamlphp/data/oid4vp_sessions
mkdir -p /var/www/html/simplesamlphp/data/oid4vp_cache

# Permissions: only the web server may read and write
chown www-data:www-data /var/www/html/simplesamlphp/data/oid4vp_sessions
chown www-data:www-data /var/www/html/simplesamlphp/data/oid4vp_cache
chmod 700 /var/www/html/simplesamlphp/data/oid4vp_sessions
chmod 700 /var/www/html/simplesamlphp/data/oid4vp_cache
```

> **Important**: `datadir` **must live outside the document root**. Session files hold the
> attributes of the already-verified credential. The module resolves the path with
> `Configuration::getPathValue()`, which interprets it relative to the SimpleSAMLphp base
> directory; if `datadir` points inside `public/`, those files would be served over HTTP.
> Quick check after a test run:
>
> ```bash
> ls /var/www/html/simplesamlphp/public/data 2>/dev/null && echo "PROBLEM: datadir inside the docroot"
> ```

> **Note**: if SimpleSAMLphp has `store.type => 'sql'` configured in `config/config.php`,
> the module automatically uses the SQL database for sessions instead of files. The cache
> stays on disk either way.

---

## 7. Manual test: the full flow with a simulated wallet

This is the most valuable test. It reproduces what a EUDI Wallet does, using the simulated
wallet shipped with the module.

### 7.1 Start the flow from the browser

1. Open a browser and reach an SP that uses your IdP (or use SimpleSAMLphp's own test SP).
2. On the MultiAuth screen, pick **"Present EducationalID"**.
3. The QR page appears with:
   - a QR code,
   - a countdown (5:00),
   - the status "Waiting for credential presentation...".

4. **Note down** from the page (view source, or the JS console):
   - `sessionId`: the session UUID
   - `openidUri`: the `openid://...` URI
   - `authState`: the SimpleSAMLphp state ID
   - `statusUrl`: the polling URL

### 7.2 The simulated wallet

The module ships one at **`tests/test_wallet.php`**. It is the reference implementation of
this test — do not copy it into your own notes, because a copy drifts: it mirrors what real
wallets do, including taking the audience from `client_id` rather than `iss`.

What it does:

1. Downloads the signed JWT Authorization Request (JAR) from `request_uri`.
2. Prints its claims, so you can check `client_id`, `response_uri`, `nonce` and `state`.
3. Generates an in-memory EC P-256 key pair for a test issuer and a test holder.
4. Builds an EducationalID credential, wraps it in a Verifiable Presentation, signs both
   with ES256.
5. Posts the result to `/direct_post` and reports the verifier's answer.

### 7.3 Run the test

```bash
# 1. In the browser, start the OID4VP flow and note the request_uri URL
#    (it is inside the QR, or in the data-openid-uri attribute of #oid4vp-app)

# 2. Extract request_uri from the openid:// URI:
#    openid://?client_id=...&request_uri=https%3A%2F%2Fidp.example.org%2F...%2Frequest_uri%2F<session-id>

# 3. Run the simulated wallet
cd /var/www/html/simplesamlphp/modules/oid4vp/
php tests/test_wallet.php "https://idp.example.org/simplesaml/module.php/oid4vp/request_uri/<session-id>"

# Add --insecure (or -k) to skip TLS verification against a self-signed test IdP
```

### 7.4 What to expect

If everything works:

1. The simulated wallet prints:
   ```
   === Step 1: GET request_uri ===
   JAR received...
   JAR claims:
     iss:           https://idp.example.org
     client_id:     https://idp.example.org
     response_type: vp_token
     ...

   === Step 2: Build the VP with the EducationalID ===
   VC JWT generated (1234 bytes)
   VP JWT generated (2345 bytes)

   === Step 3: POST direct_post ===
   Response: HTTP 200
   {"status":"ok"}

   *** SUCCESS: VP verified ***
   ```

2. In the browser, polling detects `completed` and redirects automatically.
3. SimpleSAMLphp issues the SAML assertion with the mapped attributes.

> **Important**: the test script generates its keys in memory, so `did:key:zTestIssuer123`
> is not a resolvable `did:key`. For the full verification to pass, the configuration must
> leave `trusted_issuers` empty and `ebsi_trust_registry` at `null` (development mode,
> which accepts any issuer with a warning in the log). A `did:key` has no trust network, so
> this is the one case where that applies.

### 7.5 Manual test with curl, step by step

If you would rather drive each step yourself:

```bash
# Base variables
BASE="https://idp.example.org/simplesaml/module.php/oid4vp"
SESSION_ID="<the-session-uuid>"

# Step 1: fetch the JAR
curl -k -s "$BASE/request_uri/$SESSION_ID" \
  -H "Accept: application/oauth-authz-req+jwt" \
  -o jar.jwt

# Inspect the JAR (decode the payload without verifying)
cat jar.jwt | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# Claims that matter:
#   iss / client_id -> the configured verifier_id. Wallets echo client_id back as the
#                      VP's 'aud', and the verifier checks it (step 5 of the pipeline):
#                      if it is missing, EVERY presentation fails the audience check.
#   response_uri    -> the /direct_post URL; must be reachable from the wallet
#   nonce / state   -> nonce is validated inside the VP; state links back to the session

# Step 2: check the status (should be "pending")
curl -k -s "$BASE/status/$SESSION_ID" | python3 -m json.tool
# {"status": "pending"}

# Step 3: POST direct_post (you need the VP JWT produced by the script)
curl -k -s -X POST "$BASE/direct_post" \
  -d "vp_token=<VP_JWT_HERE>" \
  -d "state=<STATE_FROM_THE_JAR>" \
  -d "presentation_submission={}"
# {"status": "ok"}

# Step 4: check the status again (should be "completed")
curl -k -s "$BASE/status/$SESSION_ID" | python3 -m json.tool
# {"status": "completed"}
```

---

## 8. Unit tests with PHPUnit

### 8.1 Run the tests

```bash
cd /var/www/html/simplesamlphp/modules/oid4vp/

# Install the dev dependencies
composer install

# Run every test
./vendor/bin/phpunit

# Run a single file
./vendor/bin/phpunit tests/Mapping/CredentialMapperTest.php
./vendor/bin/phpunit tests/Crypto/JwtHandlerTest.php
./vendor/bin/phpunit tests/Verification/PresentationVerifierTest.php
./vendor/bin/phpunit tests/Verification/TrustChainResolverTest.php
./vendor/bin/phpunit tests/Store/SessionStoreTest.php

# Run a single test
./vendor/bin/phpunit --filter testResolveDidBlueFallsBackToPreAndDesOn404
```

### 8.2 Expected output

```
PHPUnit 10.x

Testing OID4VP Module Tests

................................................  48 / 48 (100%)

Time: 00:00.150, Memory: 12.00 MB

OK (48 tests, 113 assertions)
```

### 8.3 What is covered

| File | Tests | What it checks |
|---|---|---|
| `TrustChainResolverTest` | 16 | Network selection by DID method, EBSI and BLUE retry chains, TIR lookups, `did:jwk` and `did:web` resolution, trust semantics |
| `CredentialMapperTest` | 14 | Friendly/OID mapping, array values, required fields, custom overrides |
| `JwtHandlerTest` | 10 | JWT header decoding, both `did:key` formats, base58 round-trip, unsupported methods |
| `PresentationVerifierTest` | 5 | Invalid JWT, wrong algorithm, missing `kid`, constructor |
| `SessionStoreTest` | 3 | Class exists, timeout constructor, public methods |

The network tests use mocked HTTP responses, so they neither need nor touch the real EBSI
and BLUE registries.

---

## 9. Check the resulting SAML assertion

Once the OID4VP flow completes, check that the SAML attributes are what you expect.

### 9.1 Using SimpleSAMLphp's test SP

1. Go to `https://your-idp/simplesaml/module.php/core/authenticate.php`
2. Pick `multiauth`
3. Choose "Present EducationalID"
4. Complete the flow with the simulated wallet
5. The page lists the attributes received

### 9.2 Expected attributes (friendly-name mode)

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
eduPersonTargetedID        => ['<md5-of-the-did>']
```

### 9.3 Expected attributes (OID mode, with `use_oid_format => true`)

```
urn:oid:1.3.6.1.4.1.5923.1.1.1.6     => ['jgarcia@universidad.es']     (ePPN)
urn:oid:1.3.6.1.4.1.25178.1.2.9      => ['universidad.es']             (schacHO)
urn:oid:1.3.6.1.4.1.5923.1.1.1.9     => ['student@universidad.es']     (ePSA)
urn:oid:1.3.6.1.4.1.5923.1.1.1.1     => ['student']                    (ePAff)
urn:oid:2.16.840.1.113730.3.1.241    => ['Juan Garcia Lopez']          (displayName)
urn:oid:2.5.4.3                      => ['Juan Garcia Lopez']          (cn)
urn:oid:2.5.4.4                      => ['Garcia Lopez']               (sn)
urn:oid:2.5.4.42                     => ['Juan']                       (givenName)
urn:oid:0.9.2342.19200300.100.1.3    => ['jgarcia@universidad.es']     (mail)
urn:oid:0.9.2342.19200300.100.1.1    => ['jgarcia']                    (uid)
```

> **On `eduPersonTargetedID`**: the module derives it as `md5(credentialSubject.id)`. It is
> stable per subject but **not** per relying party, so it does not provide the pairwise
> privacy the attribute's name implies. Decide whether that suits your federation before
> going to production.

### 9.4 Interaction with authproc filters

The authproc filters defined in `saml20-idp-hosted.php` run **after** the OID4VP mapping:

- **Filter 50 (name2oid)**: with `use_oid_format => false`, this filter converts the
  friendly names to OIDs. With `use_oid_format => true`, the attributes are already OIDs
  and the filter leaves them alone.
- **Filter 60 (eduPersonTargetedID)**: generates a targetedID from `mail`. Since OID4VP
  already generates one from the credential subject's DID, **you will get two values** when
  `mail` is present. Consider disabling this filter for OID4VP sessions, or making it check
  whether `eduPersonTargetedID` already exists.
- **Filter 70 (ScopeAttribute)**: builds `eduPersonScopedAffiliation` from
  `eduPersonAffiliation` + `schacHomeOrganization`. If OID4VP already provided
  `eduPersonScopedAffiliation`, the filter overwrites it. Decide whether that is what you
  want.

---

## 10. Error cases worth testing

### 10.1 Expired session

```bash
# Wait more than 5 minutes after generating the QR, then POST direct_post
curl -k -X POST "$BASE/direct_post" \
  -d "vp_token=xxx" -d "state=<expired-state>"
# Expected: 400 {"error":"invalid_request","error_description":"Unknown or expired state"}
```

### 10.2 Wrong nonce

Change the nonce inside the VP JWT (use one that differs from the JAR's):

```
# Expected: 400 {"error":"invalid_presentation","error_description":"VP nonce mismatch"}
```

### 10.3 Wrong VC type

Send a VP whose VC is not a `VerifiableEducationalID`:

```
# Expected: 400 {"error":"invalid_presentation","error_description":"VC does not contain required type: VerifiableEducationalID"}
```

### 10.4 Missing required fields

Send a VC whose `credentialSubject` lacks one of the fields the EducationalID schema marks
as required (`id`, `identifier`, `eduPersonScopedAffiliation`):

```
# Expected: 400 {"error":"invalid_presentation","error_description":"VC missing required fields: identifier, eduPersonScopedAffiliation"}
```

The IdP log also records the fields the credential **does** carry, which tells an
incomplete credential apart from an issuer using different naming:

```
OID4VP: VC missing required fields: identifier, eduPersonScopedAffiliation (present: id, body)
```

If the deployment demands extra attributes through `required_attributes`, the same error
appears with those field names.

### 10.5 Untrusted issuer (with `trusted_issuers` configured)

Set `trusted_issuers => ['did:ebsi:zTrustedOnly']` and send a VC from a different issuer:

```
# Expected: 400 {"error":"invalid_presentation","error_description":"VC issuer is not trusted: did:key:zTestIssuer123"}
```

### 10.6 Double submission

Send the same VP twice to `/direct_post`:

```
# First time:  200 {"status":"ok"}
# Second time: 400 {"error":"invalid_request","error_description":"Session already processed"}
```

### 10.7 Polling after expiry

```bash
# After 5 minutes
curl -k -s "$BASE/status/<session-id>"
# Expected: 200 {"status":"expired"}
```

---

## 11. Troubleshooting

### 11.1 SimpleSAMLphp logs

The module's log lines are prefixed with `OID4VP:`:

```bash
# Typical location
tail -f /var/log/simplesamlphp/simplesamlphp.log | grep OID4VP

# Or, when logging goes to syslog
journalctl -f | grep OID4VP

# In a container
docker logs -f sso_backend 2>&1 | grep OID4VP
```

Key messages:

| Level | Message | Meaning |
|---|---|---|
| INFO | `VP verified successfully for session <uuid>` | The presentation passed verification |
| INFO | `Authentication completed successfully` | SAML assertion issued |
| INFO | `[EBSI] DID not found, trying Conformance` | A retry chain kicked in — informational |
| WARNING | `VP verification failed: ...` | VP/VC verification error |
| WARNING | `No trust source configured for issuer DID method` | Development mode is active |
| ERROR | `Failed to load auth state: ...` | The SimpleSAMLphp session cookie expired |

### 11.2 Common problems

**"Signing key not found"**
```
Cause: The ES256 key is not at the configured path, or certdir points elsewhere.
Fix:   Check that cert/oid4vp.pem exists and is readable by the web server user.
       ls -la /var/www/html/simplesamlphp/cert/oid4vp.pem
       The module tries the path as given first, then relative to 'certdir'
       (resolved against the SimpleSAMLphp base directory, not the working directory).
```

**"Cannot create session directory"**
```
Cause: data/oid4vp_sessions/ does not exist, or has the wrong permissions.
Fix:   mkdir -p data/oid4vp_sessions && chown www-data:www-data data/oid4vp_sessions
```

**Session files show up in public/data/**
```
Cause: datadir points inside the document root (see section 6).
Fix:   Set 'datadir' in config/config.php to a path outside public/.
       This is a security problem: those files hold the attributes of the
       verified credential.
```

**"cURL error 60: SSL certificate problem: unable to get local issuer certificate"**
```
Cause: The registry server sends an incomplete chain (usually the leaf without its
       intermediate). Browsers fetch the intermediate over AIA; curl does not, so
       PHP cannot build the chain.
       api.blue.rediris.es had this until October 2026; RedIRIS fixed it at source
       and all three BLUE environments now validate without any patching.
Fix:   The right fix is on the server, which should send the full chain. As a
       stopgap, add the intermediate to the system trust store, verifying it
       against its root first:
       openssl x509 -inform DER -in <intermediate>.cer -out /tmp/int.pem
       openssl verify -CAfile /etc/ssl/certs/<ROOT>.pem /tmp/int.pem
       cp /tmp/int.pem /usr/local/share/ca-certificates/ && update-ca-certificates
See:   Inspect what chain a host sends:
       openssl s_client -connect <host>:443 -servername <host> -showcerts
```

**"[BLUE] DID not found in any registry" / "[EBSI] DID not found..."**
```
Cause: The issuer's or holder's DID is not published in that network's registry, or
       the IdP has no outbound HTTPS to the registries.
Fix:   - Check connectivity: curl -sI https://api.blue.rediris.es/did-registry/v5
       - Confirm the right environment (PROD/PRE/DES) via 'trust_networks'
       - Read the log: the INFO lines say which retries were attempted
```

**"VC missing required fields: ..."**
```
Cause: The credential lacks one of the required fields. By default only the ones the
       EducationalID schema itself marks as required are demanded:
       id, identifier, eduPersonScopedAffiliation.
Fix:   The log also lists the fields the credential DOES carry ("present: ..."),
       which shows whether the issuer uses different naming.
       If your deployment needs more attributes, declare them in the auth source's
       'required_attributes'. Demanding more than the schema rejects valid credentials.
```

**"VC issuer is not registered in the BLUE/EBSI Trusted Issuers Registry"**
```
Cause: The issuer resolves correctly but is not accredited in its network's TIR.
Fix:   - Check the issuer's accreditation in the corresponding TIR
       - For testing, add its DID to 'trusted_issuers' (checked before the TIR)
```

**"VP JWT header missing kid", or the holder's key fails to resolve**
```
Cause: Usually a did:key in the EBSI format (jwk_jcs-pub, multicodec 0xeb51), which
       older versions of the module could not decode.
Fix:   Supported since v1.0.0. If it persists, check that the JWT uses ES256 and that
       the kid is a DID of a supported method (see section 4.4).
```

**"VP audience mismatch"**
```
Cause: The 'aud' the wallet returned does not match 'verifier_id'. Wallets take it
       from the Authorization Request's client_id.
Fix:   Set 'verifier_id' to the IdP's public URL, exactly as the wallet reaches it.
```

**"Failed to load ES256 private key"**
```
Cause: The key is not EC P-256, or is in the wrong format.
Fix:   openssl ec -in cert/oid4vp.pem -text -noout
       Must print "ASN1 OID: prime256v1"
```

**The QR does not render (blank page or JS error)**
```
Cause: qrcode.min.js did not load, or there is a Twig configuration error.
Fix:   Open the browser console (F12) and look for JS errors.
       The script is served by the module itself:
       /simplesaml/module.php/oid4vp/assets/qrcode.min.js
```

**The "Open EUDI Wallet" button appears instead of the QR on a desktop**
```
Cause: Intentional when the viewport is under 480px or the device is touch-primary:
       you cannot scan the screen you are holding.
Fix:   None needed. Widening the window brings the QR back.
```

**Changes to the module's CSS/JS do not show up in the browser**
```
Cause: SimpleSAMLphp caches assets with a ?tag= parameter that does not change when
       the files are replaced.
Fix:   Force-reload in the browser (Cmd/Ctrl + Shift + R).
```

**The QR page clashes with the theme's login screen**
```
Cause: By default it extends 'base.twig', SimpleSAMLphp's generic layout.
Fix:   Point 'template_base' at the theme's login layout.
       When more wrapper markup is needed (cards, grids), the theme can override the
       template at themes/<Theme>/oid4vp/qrcode.twig.
```

**Polling never detects "completed"**
```
Cause: The wallet could not POST to /direct_post (firewall, unreachable host, etc.)
Fix:   - Check that /direct_post is reachable from the wallet's network
       - Look for 4xx/5xx on /direct_post in the web server logs
       - Ensure valid HTTPS (EUDI wallets reject untrusted certificates)
```

**"Authentication session expired" at direct_post**
```
Cause: The SimpleSAMLphp session cookie expired before the wallet answered.
Fix:   Raise session.cookie.lifetime in SimpleSAMLphp's config/config.php,
       or lower the module's session_timeout.
```

### 11.3 Inspect the SessionStore

```bash
# Active sessions (file-based store)
ls -la /var/www/html/simplesamlphp/data/oid4vp_sessions/

# Contents of one session
cat /var/www/html/simplesamlphp/data/oid4vp_sessions/<uuid>.json | python3 -m json.tool

# Clear expired sessions by hand
find /var/www/html/simplesamlphp/data/oid4vp_sessions/ -name "*.json" -mmin +6 -delete
```

### 11.4 Check the module's routes

```bash
# The routes live in:
cat /var/www/html/simplesamlphp/modules/oid4vp/routing/routes/routes.yaml

# Check that the endpoints answer:
curl -k -s -o /dev/null -w "%{http_code}" "$BASE/qrpage"
# 400 (missing AuthState — correct, it means the route works)

curl -k -s -o /dev/null -w "%{http_code}" "$BASE/status/nonexistent"
# 200 with {"status":"expired"} — correct

curl -k -s -o /dev/null -w "%{http_code}" "$BASE/request_uri/nonexistent"
# 404 with {"error":"session_not_found"} — correct
```
