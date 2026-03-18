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

    // Static list of trusted VC issuer DIDs.
    // If empty and no EBSI registry is configured, all issuers are accepted (dev mode).
    'trusted_issuers' => [
        // 'did:ebsi:z...',
        // 'did:key:z...',
    ],

    // Attribute mapping from VC credentialSubject fields to SAML attribute names.
    // Override individual mappings here. Default mappings are built into CredentialMapper.
    'attribute_map' => [
        // 'commonName' => 'cn',
        // 'familyName' => 'sn',
    ],

    // EBSI configuration (disabled by default — day 1 uses did:key + static trust).
    'ebsi' => [
        'enabled' => false,
        'did_registry' => 'https://api-pilot.ebsi.eu/did-registry/v5',
        'trust_registry' => 'https://api-pilot.ebsi.eu/trusted-issuers-registry/v5',
        'schema_registry' => 'https://api-pilot.ebsi.eu/trusted-schemas-registry/v3',
        // 'proxy' => 'https://api-pilot.ebsi.eu/proxy',  // For StatusList2021 revocation
    ],
];
