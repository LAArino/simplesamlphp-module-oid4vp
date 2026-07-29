<?php

/*
 * Copyright (c) 2024-2026 LAArino / Universitat Rovira i Virgili
 *
 * Licensed under the EUPL, Version 1.2 (the "Licence");
 * you may not use this file except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * This module depends on SimpleSAMLphp (LGPL-2.1-or-later),
 * which is NOT included in this distribution.
 */

declare(strict_types=1);

namespace SimpleSAML\Module\oid4vp\Auth\Source;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils;

/**
 * OID4VP Authentication Source for SimpleSAMLphp.
 *
 * Authenticates users by verifying a Verifiable Presentation (VP)
 * containing an EducationalID credential, presented via QR code scan
 * from a EUDI Wallet following the OID4VP protocol (DC4EU RFC-002).
 *
 * Flow:
 *   1. User selects "Present EducationalID" in MultiAuth selector
 *   2. authenticate() saves state and redirects to /qrpage
 *   3. QR page shows openid:// URI for wallet to scan
 *   4. Wallet fetches JAR from /request_uri/{id}, sends VP to /direct_post
 *   5. Browser polls /status/{id} until completed
 *   6. Browser redirects to /qrpage?complete=1 → completeAuth()
 *
 * This auth source never returns from authenticate() — it always redirects.
 */
class OID4VP extends Auth\Source
{
    private string $presentationDefinitionType;
    private string $verifierId;
    private string $signingCert;
    private string $signingKey;
    private ?string $verifierKid;
    private int $sessionTimeout;
    private array $trustedIssuers;
    private ?string $ebsiTrustRegistry;
    private array $trustNetworks;
    private ?array $requiredAttributes;
    private bool $useOidFormat;
    private array $attributeMap;
    private string $template;
    private string $templateBase;

    public function __construct(array $info, array $config)
    {
        parent::__construct($info, $config);

        $this->presentationDefinitionType = $config['presentation_definition_type']
            ?? 'VerifiableEducationalID';
        $this->verifierId = $config['verifier_id']
            ?? Configuration::getInstance()->getString('baseurlpath', 'https://idp.example.org');
        $this->signingCert = $config['signing_cert'] ?? 'cert/oid4vp.crt';
        $this->signingKey = $config['signing_key'] ?? 'cert/oid4vp.pem';
        $this->verifierKid = $config['verifier_kid'] ?? null;
        $this->sessionTimeout = $config['session_timeout'] ?? 300;
        $this->trustedIssuers = $config['trusted_issuers'] ?? [];
        $this->ebsiTrustRegistry = $config['ebsi_trust_registry'] ?? null;
        $this->trustNetworks = $config['trust_networks'] ?? [];
        // null keeps the EducationalID schema's own required set
        $this->requiredAttributes = $config['required_attributes'] ?? null;
        $this->useOidFormat = $config['use_oid_format'] ?? false;
        $this->attributeMap = $config['attribute_map'] ?? [];

        // Theming: 'template' swaps the whole QR page template, 'template_base'
        // only swaps the layout our default template extends. Themes that ship
        // their own full-screen login layout (e.g. themeRedIRIS's baseSSO.twig)
        // usually only need 'template_base'.
        $this->template = $config['template'] ?? 'oid4vp:qrcode.twig';
        $this->templateBase = $config['template_base'] ?? 'base.twig';
    }

    /**
     * Start authentication: save config in state and redirect to QR page.
     *
     * Does not return — redirects to /module.php/oid4vp/qrpage.
     */
    public function authenticate(array &$state): void
    {
        // Store all config in state so the controller can access it
        $state['oid4vp:AuthSourceId'] = $this->authId;
        $state['oid4vp:verifier_id'] = $this->verifierId;
        $state['oid4vp:verifier_kid'] = $this->verifierKid;
        $state['oid4vp:signing_cert'] = $this->signingCert;
        $state['oid4vp:signing_key'] = $this->signingKey;
        $state['oid4vp:session_timeout'] = $this->sessionTimeout;
        $state['oid4vp:trusted_issuers'] = $this->trustedIssuers;
        $state['oid4vp:ebsi_trust_registry'] = $this->ebsiTrustRegistry;
        $state['oid4vp:trust_networks'] = $this->trustNetworks;
        $state['oid4vp:required_attributes'] = $this->requiredAttributes;
        $state['oid4vp:use_oid_format'] = $this->useOidFormat;
        $state['oid4vp:attribute_map'] = $this->attributeMap;
        $state['oid4vp:presentation_definition_type'] = $this->presentationDefinitionType;
        $state['oid4vp:template'] = $this->template;
        $state['oid4vp:template_base'] = $this->templateBase;

        // Save state and redirect to the QR page
        $stateId = Auth\State::saveState($state, 'oid4vp:auth');

        $url = Module::getModuleURL('oid4vp/qrpage');
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, ['AuthState' => $stateId]);
    }
}
