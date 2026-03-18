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

use SimpleSAML\Module\oid4vp\Crypto\JwtHandler;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;

/**
 * Verifies OID4VP Verifiable Presentations (VP) and embedded Verifiable Credentials (VC).
 *
 * Verification pipeline (12 steps):
 *   1.  Decode VP JWT header → extract holder DID from kid
 *   2.  Resolve holder public key (did:key)
 *   3.  Verify VP JWT signature
 *   4.  Check nonce matches expected nonce
 *   5.  Check aud matches verifier_client_id
 *   6.  Check exp not expired
 *   7.  Parse presentation_submission → locate VC in $.vp.verifiableCredential[0]
 *   8.  Decode VC JWT → extract issuer DID
 *   9.  Resolve issuer public key
 *   10. Verify VC JWT signature
 *   11. Check type contains required type + issuer in trusted_issuers
 *   12. Extract credentialSubject
 */
class PresentationVerifier
{
    private JwtHandler $jwtHandler;
    private TrustChainResolver $trustResolver;
    private string $verifierId;

    public function __construct(
        string $verifierId,
        array $trustedIssuers = [],
        ?string $ebsiTrustRegistry = null,
        ?\GuzzleHttp\Client $httpClient = null
    ) {
        $this->verifierId = $verifierId;
        $this->jwtHandler = new JwtHandler();
        $this->trustResolver = new TrustChainResolver(
            $trustedIssuers,
            $ebsiTrustRegistry,
            $httpClient
        );
    }

    /**
     * Verify a VP token (JWT) and return the extracted credential subject.
     *
     * @param string $vpToken JWT-encoded Verifiable Presentation
     * @param string $expectedNonce The nonce from the authorization request
     * @return array{credential_subject: array, issuer: string, vc_type: array}
     * @throws VerificationException
     */
    public function verify(string $vpToken, string $expectedNonce): array
    {
        // Step 1: Decode VP JWT header → extract holder DID
        $vpHeader = $this->jwtHandler->decodeHeader($vpToken);

        $vpAlg = $vpHeader['alg'] ?? null;
        if ($vpAlg !== 'ES256') {
            throw new VerificationException(
                'VP JWT must use ES256 algorithm, got: ' . ($vpAlg ?? 'none')
            );
        }

        $holderKid = $vpHeader['kid'] ?? null;
        if ($holderKid === null) {
            throw new VerificationException('VP JWT header missing kid (holder DID)');
        }

        // Step 2: Resolve holder's public key
        $holderKey = $this->trustResolver->resolvePublicKey($holderKid);

        // Step 3: Verify VP JWT signature
        $vpPayload = $this->jwtHandler->verifyJwt($vpToken, $holderKey);

        // Step 4: Validate nonce
        $vpNonce = $vpPayload['nonce'] ?? null;
        if ($vpNonce !== $expectedNonce) {
            throw new VerificationException('VP nonce mismatch');
        }

        // Step 5: Validate audience
        $vpAud = $vpPayload['aud'] ?? null;
        if ($vpAud !== $this->verifierId) {
            throw new VerificationException(
                'VP audience mismatch: expected ' . $this->verifierId . ', got ' . ($vpAud ?? 'none')
            );
        }

        // Step 6: Check VP expiration
        if (isset($vpPayload['exp']) && $vpPayload['exp'] < time()) {
            throw new VerificationException('VP has expired');
        }

        // Step 7: Extract VC from VP
        $vp = $vpPayload['vp'] ?? null;
        if ($vp === null || !isset($vp['verifiableCredential'])) {
            throw new VerificationException('VP missing verifiableCredential');
        }

        $vcTokens = $vp['verifiableCredential'];
        if (!is_array($vcTokens) || count($vcTokens) === 0) {
            throw new VerificationException('VP contains no verifiable credentials');
        }

        // Step 8-12: Verify the first VC (EducationalID)
        return $this->verifyCredential($vcTokens[0]);
    }

    /**
     * Verify an individual Verifiable Credential JWT.
     *
     * @return array{credential_subject: array, issuer: string, vc_type: array}
     * @throws VerificationException
     */
    private function verifyCredential(string $vcToken): array
    {
        // Step 8: Decode VC header → extract issuer DID
        $vcHeader = $this->jwtHandler->decodeHeader($vcToken);

        $vcAlg = $vcHeader['alg'] ?? null;
        if ($vcAlg !== 'ES256') {
            throw new VerificationException('VC JWT must use ES256 algorithm');
        }

        $issuerKid = $vcHeader['kid'] ?? null;
        if ($issuerKid === null) {
            throw new VerificationException('VC JWT header missing kid (issuer DID)');
        }

        // Step 9: Resolve issuer's public key
        $issuerKey = $this->trustResolver->resolvePublicKey($issuerKid);

        // Step 10: Verify VC JWT signature
        $vcPayload = $this->jwtHandler->verifyJwt($vcToken, $issuerKey);

        // Step 11: Extract and verify issuer
        $issuer = $vcPayload['iss'] ?? ($vcPayload['vc']['issuer'] ?? null);
        if ($issuer === null) {
            throw new VerificationException('VC missing issuer');
        }
        $this->trustResolver->verifyIssuerTrust($issuer);

        // Check VC expiration
        if (isset($vcPayload['exp']) && $vcPayload['exp'] < time()) {
            throw new VerificationException('VC has expired');
        }

        // Check not-before (with 60s clock skew tolerance)
        if (isset($vcPayload['nbf']) && $vcPayload['nbf'] > time() + 60) {
            throw new VerificationException('VC is not yet valid');
        }

        // Step 12: Extract credentialSubject
        $vc = $vcPayload['vc'] ?? null;
        if ($vc === null || !isset($vc['credentialSubject'])) {
            throw new VerificationException('VC missing credentialSubject');
        }

        $vcType = $vc['type'] ?? [];

        return [
            'credential_subject' => $vc['credentialSubject'],
            'issuer' => $issuer,
            'vc_type' => $vcType,
        ];
    }
}
