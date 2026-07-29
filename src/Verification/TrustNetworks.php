<?php

/*
 * Copyright (c) 2024-2026 LAArino / Universitat Rovira i Virgili
 *
 * Licensed under the EUPL, Version 1.2 (the "Licence");
 * you may not use this file except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 */

declare(strict_types=1);

namespace SimpleSAML\Module\oid4vp\Verification;

/**
 * Trust network registry: maps DID method prefixes to their network APIs.
 *
 * Each network provides a DID Registry, a Trusted Issuers Registry (TIR) and
 * a Trusted Schemas Registry, with optional fallback mirrors (tried on network
 * errors) and alternate environments (tried on 404).
 *
 * Built-in networks:
 *   did:ebsi — EBSI Pilot, RedIRIS mirror fallback, Conformance alternate
 *   did:blue — BLUE PROD, with PRE and DES alternates
 *
 * Deployments can override or extend networks via the 'trust_networks'
 * config option (per-authsource or module config); user entries replace
 * the built-in entry for the same DID method prefix.
 */
class TrustNetworks
{
    public const DEFAULTS = [
        'did:ebsi' => [
            'name' => 'EBSI',
            'config' => [
                'did_registry_url' => 'https://api-pilot.ebsi.eu/did-registry/v5',
                'trusted_issuers_registry_url' => 'https://api-pilot.ebsi.eu/trusted-issuers-registry/v5',
                'trusted_schemas_registry_url' => 'https://api-pilot.ebsi.eu/trusted-schemas-registry/v3',
                // RedIRIS mirror — used on network errors from primary
                'fallback_did_registry_url' => 'https://api-pilot.ebsi.rediris.es/did-registry/v5',
                'fallback_trusted_issuers_registry_url' => 'https://api-pilot.ebsi.rediris.es/trusted-issuers-registry/v5',
                'label' => 'Pilot',
            ],
            'alternate_configs' => [
                [
                    'did_registry_url' => 'https://api-conformance.ebsi.eu/did-registry/v5',
                    'trusted_issuers_registry_url' => 'https://api-conformance.ebsi.eu/trusted-issuers-registry/v5',
                    'trusted_schemas_registry_url' => 'https://api-conformance.ebsi.eu/trusted-schemas-registry/v3',
                    'label' => 'Conformance',
                ],
            ],
        ],
        'did:blue' => [
            'name' => 'BLUE',
            'config' => [
                'did_registry_url' => 'https://api.blue.rediris.es/did-registry/v5',
                'trusted_issuers_registry_url' => 'https://api.blue.rediris.es/trusted-issuers-registry/v5',
                'trusted_schemas_registry_url' => 'https://api.blue.rediris.es/trusted-schemas-registry/v3',
                'label' => 'PROD',
            ],
            'alternate_configs' => [
                [
                    'did_registry_url' => 'https://api-pre.blue.rediris.es/did-registry/v5',
                    'trusted_issuers_registry_url' => 'https://api-pre.blue.rediris.es/trusted-issuers-registry/v5',
                    'trusted_schemas_registry_url' => 'https://api-pre.blue.rediris.es/trusted-schemas-registry/v3',
                    'label' => 'PRE',
                ],
                [
                    'did_registry_url' => 'https://api-des.blue.rediris.es/did-registry/v5',
                    'trusted_issuers_registry_url' => 'https://api-des.blue.rediris.es/trusted-issuers-registry/v5',
                    'trusted_schemas_registry_url' => 'https://api-des.blue.rediris.es/trusted-schemas-registry/v3',
                    'label' => 'DES',
                ],
            ],
        ],
    ];

    /** @var array<string, array> */
    private array $networks;

    /**
     * @param array $overrides User-supplied networks; each entry replaces the
     *                         built-in entry for the same DID method prefix.
     */
    public function __construct(array $overrides = [])
    {
        $this->networks = array_merge(self::DEFAULTS, $overrides);
    }

    /**
     * Look up the network for a DID by its method prefix (e.g. "did:blue").
     *
     * @return array|null Network entry {name, config, alternate_configs?} or null
     */
    public function forDid(string $did): ?array
    {
        $parts = explode(':', $did);
        if (count($parts) < 2) {
            return null;
        }
        $prefix = $parts[0] . ':' . $parts[1];
        return $this->networks[$prefix] ?? null;
    }
}
