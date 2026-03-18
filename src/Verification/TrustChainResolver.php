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

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oid4vp\Crypto\JwtHandler;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;

/**
 * Resolves DIDs to public keys and verifies issuer trust.
 *
 * Day 1: did:key resolution (key embedded in DID) + static trusted_issuers list.
 * Future: did:ebsi via EBSI DID Registry + Trusted Issuers Registry API + revocation.
 */
class TrustChainResolver
{
    private Client $httpClient;
    private JwtHandler $jwtHandler;
    private array $trustedIssuers;
    private ?string $ebsiTrustRegistry;

    public function __construct(
        array $trustedIssuers = [],
        ?string $ebsiTrustRegistry = null,
        ?Client $httpClient = null
    ) {
        $this->trustedIssuers = $trustedIssuers;
        $this->ebsiTrustRegistry = $ebsiTrustRegistry;
        $this->httpClient = $httpClient ?? new Client(['timeout' => 10]);
        $this->jwtHandler = new JwtHandler();
    }

    /**
     * Resolve a DID (possibly with #fragment) to a public key for JWT verification.
     *
     * Resolution order:
     *   1. did:key — key embedded in DID (day 1, native)
     *   2. did:ebsi — EBSI DID Registry (future)
     *   3. Universal Resolver fallback (development)
     *
     * @param string $kid DID with optional #fragment (e.g., "did:key:z...#key-1")
     * @return Key Public key for JWT verification
     * @throws VerificationException
     */
    public function resolvePublicKey(string $kid): Key
    {
        $did = explode('#', $kid)[0];

        if (str_starts_with($did, 'did:key:')) {
            return $this->jwtHandler->extractPublicKeyFromDid($kid);
        }

        if (str_starts_with($did, 'did:ebsi:')) {
            return $this->resolveEbsiDid($kid);
        }

        // Fallback: Universal Resolver (development/testing only)
        return $this->resolveViaUniversalResolver($kid);
    }

    /**
     * Verify that a VC issuer is trusted.
     *
     * Checks static trusted_issuers list first, then EBSI Trust Registry if configured.
     * In development mode (no issuers and no registry), accepts with a warning.
     *
     * @throws VerificationException if issuer is not trusted
     */
    public function verifyIssuerTrust(string $issuerDid): void
    {
        // Check static list
        if (in_array($issuerDid, $this->trustedIssuers, true)) {
            return;
        }

        // Check EBSI Trust Registry if configured
        if ($this->ebsiTrustRegistry !== null) {
            if ($this->checkEbsiTrustRegistry($issuerDid)) {
                return;
            }
        }

        // Development mode: no trust sources configured → accept with warning
        if (empty($this->trustedIssuers) && $this->ebsiTrustRegistry === null) {
            Logger::warning(
                'OID4VP: No trusted issuers or EBSI registry configured. '
                . 'Accepting issuer without trust verification: ' . $issuerDid
            );
            return;
        }

        throw new VerificationException('VC issuer is not trusted: ' . $issuerDid);
    }

    /**
     * Resolve a did:ebsi DID by fetching the DID document from EBSI DID Registry.
     */
    private function resolveEbsiDid(string $kid): Key
    {
        $did = explode('#', $kid)[0];
        $fragment = str_contains($kid, '#') ? explode('#', $kid)[1] : null;

        try {
            $url = 'https://api-pilot.ebsi.eu/did-registry/v5/identifiers/' . urlencode($did);
            $response = $this->httpClient->get($url, [
                'headers' => ['Accept' => 'application/did+json'],
            ]);

            $didDocument = json_decode((string) $response->getBody(), true);
            return $this->extractKeyFromDidDocument($didDocument, $fragment);
        } catch (GuzzleException $e) {
            throw new VerificationException('Failed to resolve EBSI DID ' . $did . ': ' . $e->getMessage());
        }
    }

    /**
     * Fallback: resolve DID via Universal Resolver (development/testing).
     */
    private function resolveViaUniversalResolver(string $kid): Key
    {
        $did = explode('#', $kid)[0];
        $fragment = str_contains($kid, '#') ? explode('#', $kid)[1] : null;

        try {
            $url = 'https://dev.uniresolver.io/1.0/identifiers/' . urlencode($did);
            $response = $this->httpClient->get($url, [
                'headers' => ['Accept' => 'application/json'],
            ]);

            $result = json_decode((string) $response->getBody(), true);
            $didDocument = $result['didDocument'] ?? null;
            if ($didDocument === null) {
                throw new VerificationException('Universal Resolver returned no DID document for ' . $did);
            }

            return $this->extractKeyFromDidDocument($didDocument, $fragment);
        } catch (GuzzleException $e) {
            throw new VerificationException('Failed to resolve DID via Universal Resolver: ' . $e->getMessage());
        }
    }

    /**
     * Check if an issuer is registered in the EBSI Trusted Issuers Registry.
     */
    private function checkEbsiTrustRegistry(string $issuerDid): bool
    {
        try {
            $url = rtrim($this->ebsiTrustRegistry, '/') . '/issuers/' . urlencode($issuerDid);
            $response = $this->httpClient->get($url, [
                'headers' => ['Accept' => 'application/json'],
            ]);

            if ($response->getStatusCode() === 200) {
                $body = json_decode((string) $response->getBody(), true);
                return isset($body['did']) && $body['did'] === $issuerDid;
            }
        } catch (GuzzleException $e) {
            Logger::warning(
                'OID4VP: EBSI Trust Registry check failed for ' . $issuerDid . ': ' . $e->getMessage()
            );
        }

        return false;
    }

    /**
     * Extract a verification method public key from a DID document.
     */
    private function extractKeyFromDidDocument(array $didDocument, ?string $fragment): Key
    {
        $verificationMethods = $didDocument['verificationMethod'] ?? [];

        foreach ($verificationMethods as $vm) {
            if ($fragment !== null) {
                $vmId = $vm['id'] ?? '';
                $vmFragment = str_contains($vmId, '#') ? explode('#', $vmId)[1] : $vmId;
                if ($vmFragment !== $fragment) {
                    continue;
                }
            }

            if (isset($vm['publicKeyJwk'])) {
                return JWK::parseKey($vm['publicKeyJwk'], 'ES256');
            }
        }

        throw new VerificationException('No suitable verification method found in DID document');
    }
}
