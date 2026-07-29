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

namespace SimpleSAML\Module\oid4vp\Mapping;

/**
 * Maps EducationalID credentialSubject fields to SIR2 SAML attributes.
 *
 * The mapping follows the DC4EU <-> SIR2 attribute mapping table.
 * All values are wrapped in arrays (SSP convention: ['mail' => ['user@example.org']]).
 */
class CredentialMapper
{
    /**
     * OID-format mapping: credentialSubject field -> SAML OID attribute.
     */
    private const OID_MAP = [
        'eduPersonPrincipalName'     => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',
        'schacHomeOrganization'      => 'urn:oid:1.3.6.1.4.1.25178.1.2.9',
        'eduPersonScopedAffiliation' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.9',
        'eduPersonPrimaryAffiliation'=> 'urn:oid:1.3.6.1.4.1.5923.1.1.1.5',
        'eduPersonAffiliation'       => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
        'eduPersonAssurance'         => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.11',
        'displayName'                => 'urn:oid:2.16.840.1.113730.3.1.241',
        'commonName'                 => 'urn:oid:2.5.4.3',
        'familyName'                 => 'urn:oid:2.5.4.4',
        'firstName'                  => 'urn:oid:2.5.4.42',
        'mail'                       => 'urn:oid:0.9.2342.19200300.100.1.3',
        'schacPersonalUniqueCode'    => 'urn:oid:1.3.6.1.4.1.25178.1.2.14',
        'identifier'                 => 'urn:oid:0.9.2342.19200300.100.1.1',
    ];

    /**
     * Friendly-name mapping: credentialSubject field -> SAML friendly name.
     */
    private const FRIENDLY_MAP = [
        'eduPersonPrincipalName'     => 'eduPersonPrincipalName',
        'schacHomeOrganization'      => 'schacHomeOrganization',
        'eduPersonScopedAffiliation' => 'eduPersonScopedAffiliation',
        'eduPersonPrimaryAffiliation'=> 'eduPersonAffiliation',
        'eduPersonAffiliation'       => 'eduPersonAffiliation',
        'eduPersonAssurance'         => 'eduPersonAssurance',
        'displayName'                => 'displayName',
        'commonName'                 => 'cn',
        'familyName'                 => 'sn',
        'firstName'                  => 'givenName',
        'mail'                       => 'mail',
        'schacPersonalUniqueCode'    => 'schacPersonalUniqueCode',
        'identifier'                 => 'uid',
    ];

    private bool $useOidFormat;
    private array $customMap;
    private array $requiredAttributes;

    /**
     * @param bool $useOidFormat Use OID format (true) or friendly names (false)
     * @param array $customMap Optional custom mapping overrides (vcField => samlAttr)
     * @param array|null $requiredAttributes credentialSubject fields a presentation
     *        must carry; null uses the schema's own required set
     */
    public function __construct(
        bool $useOidFormat = false,
        array $customMap = [],
        ?array $requiredAttributes = null
    ) {
        $this->useOidFormat = $useOidFormat;
        $this->customMap = $customMap;
        $this->requiredAttributes = $requiredAttributes ?? self::SCHEMA_REQUIRED;
    }

    /**
     * Map a credentialSubject from an EducationalID VC to SAML attributes.
     *
     * @param array $credentialSubject The credentialSubject object from the VC
     * @return array SAML attributes (each value is an array of strings)
     */
    public function map(array $credentialSubject): array
    {
        $mapping = $this->useOidFormat ? self::OID_MAP : self::FRIENDLY_MAP;

        // Apply custom overrides
        if (!empty($this->customMap)) {
            $mapping = array_merge($mapping, $this->customMap);
        }

        $attributes = [];

        foreach ($mapping as $vcField => $samlAttr) {
            if (!isset($credentialSubject[$vcField])) {
                continue;
            }

            $value = $credentialSubject[$vcField];

            // SAML attributes are always arrays of values
            if (is_array($value)) {
                $attributes[$samlAttr] = array_map('strval', $value);
            } else {
                $attributes[$samlAttr] = [(string) $value];
            }
        }

        // Generate eduPersonTargetedID from the credential subject ID
        if (isset($credentialSubject['id'])) {
            $targetedIdAttr = $this->useOidFormat
                ? 'urn:oid:1.3.6.1.4.1.5923.1.1.1.10'
                : 'eduPersonTargetedID';
            $attributes[$targetedIdAttr] = [md5((string) $credentialSubject['id'])];
        }

        return $attributes;
    }

    /**
     * Fields the EducationalID schema itself marks as required. Identical in the
     * EBSI and BLUE schema registries.
     *
     * @see https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/zEmFZquJtANNz7XNE46thRi1E2cAfpQiXVLSBdDgLyfGP
     * @see https://api.blue.rediris.es/trusted-schemas-registry/v3/schemas/zvWtRJVNsU8x6G5rFJ4o5SGMdrGcFfQ1MpBpw8Wazj4t
     */
    public const SCHEMA_REQUIRED = [
        'id',
        'identifier',
        'eduPersonScopedAffiliation',
    ];

    /**
     * Validate that a credentialSubject contains the required fields.
     *
     * Defaults to what the EducationalID schema requires. Demanding more than the
     * schema does rejects credentials that are perfectly valid — deployments whose
     * service providers need extra attributes should opt in via the
     * 'required_attributes' configuration option instead.
     *
     * @return array List of missing required fields (empty if valid)
     */
    public function validateRequired(array $credentialSubject): array
    {
        $missing = [];
        foreach ($this->requiredAttributes as $field) {
            $value = $credentialSubject[$field] ?? null;
            if ($value === null || $value === '' || $value === []) {
                $missing[] = $field;
            }
        }

        return $missing;
    }
}
