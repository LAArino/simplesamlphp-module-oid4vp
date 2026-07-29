<?php

/**
 * Default configuration for the OID4VP module.
 *
 * Copy this file to your SimpleSAMLphp config/ directory and adjust values
 * for your deployment. Values here serve as defaults; per-authsource config
 * in authsources.php overrides these.
 */

$config = [

    // Verifier identifier — usually the IdP entity ID.
    // Used as 'iss' in the JWT Authorization Request and 'aud' verification in the VP.
    'verifier_client_id' => 'https://idp.example.org',

    // Key ID for the verifier (included in JWT header as 'kid')
    'verifier_kid' => null,

    // Path to the ES256 private key for signing JWT Authorization Requests.
    // MUST be separate from the SAML signing key. Permissions should be 0600.
    'private_key_path' => 'cert/oid4vp.pem',

    // Path to the corresponding ES256 public key/certificate.
    'public_key_path' => 'cert/oid4vp.crt',

    // OID4VP session TTL in seconds. QR codes expire after this time.
    'session_ttl' => 300,

    // Polling interval hint (seconds) — used by the browser JS.
    'poll_interval' => 2,

    // The VC type to request in the presentation definition.
    'presentation_definition' => [
        'credential_type' => 'VerifiableEducationalID',
    ],

    // Static list of trusted VC issuer DIDs, always checked first.
    // Issuers whose DID method belongs to a trust network (did:ebsi, did:blue)
    // are additionally checked against that network's Trusted Issuers Registry.
    // Dev mode: an issuer whose DID method has NO network (e.g. did:key) is
    // accepted with a warning when this list is empty and no legacy registry
    // is configured.
    'trusted_issuers' => [
        // 'did:ebsi:z...',
        // 'did:blue:z...',
        // 'did:key:z...',
    ],

    // Attribute mapping from VC credentialSubject fields to SAML attribute names.
    // Override individual mappings here. Default mappings are built into CredentialMapper.
    'attribute_map' => [
        // 'commonName' => 'cn',
        // 'familyName' => 'sn',
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

    // Legacy: single-URL Trusted Issuers Registry, checked for issuers whose
    // DID method has no trust network entry. Prefer 'trust_networks' above.
    // 'ebsi_trust_registry' => 'https://api-pilot.ebsi.eu/trusted-issuers-registry/v5',
];
