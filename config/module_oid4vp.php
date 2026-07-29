<?php

/**
 * Reference of every OID4VP authentication source option, with its default value.
 *
 * IMPORTANT: this file is a reference, not a configuration file — the module does
 * not load it. All configuration lives in the authentication source entry in
 * SimpleSAMLphp's config/authsources.php. Copy the options you need from here
 * into that entry.
 *
 * Example authsources.php entry:
 *
 *     'oid4vp' => [
 *         'oid4vp:OID4VP',
 *         'verifier_id' => 'https://idp.example.org',
 *         'signing_key' => 'oid4vp.pem',
 *         'trusted_issuers' => ['did:blue:z...'],
 *     ],
 */

return [

    // Verifier identifier — usually the IdP entity ID. Used as 'iss' in the JWT
    // Authorization Request and verified as 'aud' in the Verifiable Presentation.
    // Defaults to the 'baseurlpath' of the SimpleSAMLphp configuration.
    'verifier_id' => 'https://idp.example.org',

    // Key ID advertised in the JAR's JWT header ('kid'). null omits it.
    'verifier_kid' => null,

    // ES256 (P-256) key pair used to sign JWT Authorization Requests.
    // MUST be separate from the SAML signing keys. Paths are absolute, or
    // relative to SimpleSAMLphp's 'certdir'. The private key should be 0600.
    'signing_key' => 'oid4vp.pem',
    'signing_cert' => 'oid4vp.crt',

    // OID4VP session TTL in seconds. QR codes expire after this time.
    'session_timeout' => 300,

    // The VC type requested in the presentation definition.
    'presentation_definition_type' => 'VerifiableEducationalID',

    // Static list of trusted VC issuer DIDs, always checked first.
    // Issuers whose DID method belongs to a trust network (did:ebsi, did:blue)
    // are additionally checked against that network's Trusted Issuers Registry
    // and rejected if not registered there.
    // Development mode: an issuer whose DID method has NO network (e.g. did:key)
    // is accepted with a log warning when this list is empty and no legacy
    // registry is configured. Do not rely on this in production.
    'trusted_issuers' => [
        // 'did:ebsi:z...',
        // 'did:blue:z...',
        // 'did:key:z...',
    ],

    // Trust networks: maps DID method prefixes to their registry APIs.
    // EBSI (did:ebsi) and BLUE (did:blue) are built in with these defaults:
    //
    //   did:ebsi — EBSI Pilot (api-pilot.ebsi.eu/{did-registry,trusted-issuers-registry}/v5)
    //              + RedIRIS mirror fallback (api-pilot.ebsi.rediris.es) on network errors
    //              + Conformance alternate (api-conformance.ebsi.eu) on 404
    //   did:blue — BLUE PROD (api.blue.rediris.es/{did-registry,trusted-issuers-registry}/v5)
    //              + PRE (api-pre.blue.rediris.es) and DES (api-des.blue.rediris.es)
    //                alternates on 404
    //
    // Only add entries here to OVERRIDE a built-in network or ADD a new one;
    // an entry replaces the built-in entry for the same DID method prefix.
    'trust_networks' => [
        // Example: pin BLUE to the PRE environment only
        // 'did:blue' => [
        //     'name' => 'BLUE',
        //     'config' => [
        //         'did_registry_url' => 'https://api-pre.blue.rediris.es/did-registry/v5',
        //         'trusted_issuers_registry_url' => 'https://api-pre.blue.rediris.es/trusted-issuers-registry/v5',
        //         'trusted_schemas_registry_url' => 'https://api-pre.blue.rediris.es/trusted-schemas-registry/v3',
        //         'label' => 'PRE',
        //     ],
        //     'alternate_configs' => [],
        // ],
    ],

    // Legacy: single-URL Trusted Issuers Registry, checked only for issuers whose
    // DID method has no trust network entry. Prefer 'trust_networks' above.
    'ebsi_trust_registry' => null,

    // Attribute naming: false emits friendly names (cn, sn, mail, ...),
    // true emits OID format (urn:oid:2.5.4.3, ...).
    'use_oid_format' => false,

    // Per-field overrides of the credentialSubject → SAML attribute mapping.
    // Defaults are built into CredentialMapper.
    'attribute_map' => [
        // 'commonName' => 'cn',
        // 'familyName' => 'sn',
    ],

    // Theming of the QR page.
    //
    // 'template_base' — the layout the default template extends. Point it at
    // your theme's login layout so the QR page matches the login page instead
    // of the generic SimpleSAMLphp page. For the RedIRIS IdPnube theme:
    //     'template_base' => 'baseSSO.twig',
    //
    // 'template' — replace the QR page template entirely. Only needed when the
    // layout requires extra wrapper markup (a card, a column grid); themes can
    // also override 'oid4vp:qrcode.twig' the standard way, by shipping
    // themes/<Theme>/oid4vp/qrcode.twig.
    'template_base' => 'base.twig',
    'template' => 'oid4vp:qrcode.twig',
];
