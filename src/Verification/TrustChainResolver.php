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
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oid4vp\Crypto\JwtHandler;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;

/**
 * Resolves DIDs to public keys and verifies issuer trust across networks.
 *
 * DID resolution:
 *   did:key — resolved locally (multicodec 0x1200 P-256 and 0xeb51 jwk_jcs-pub)
 *   did:jwk — resolved locally (JWK embedded in the DID)
 *   did:web — resolved via HTTPS (W3C did:web method specification)
 *   did:ebsi, did:blue, ... — resolved via the network's DID Registry with a
 *     retry chain: primary → fallback mirror (on network error) → alternate
 *     environments (on 404). Networks come from TrustNetworks.
 *   other — Universal Resolver fallback (development/testing only)
 *
 * Issuer trust:
 *   1. Static trusted_issuers list
 *   2. The network's Trusted Issuers Registry (same retry chain)
 *   3. Legacy single-URL EBSI registry (ebsi_trust_registry option)
 *   4. Development mode: if the issuer's DID method has no network and no
 *      other trust source is configured, accept with a warning.
 *
 * Successful DID resolutions and TIR lookups are cached on disk (48h TTL)
 * under <datadir>/oid4vp_cache; caching is best-effort and failures are
 * silently ignored.
 */
class TrustChainResolver
{
    private const CACHE_TTL = 48 * 3600;

    private Client $httpClient;
    private JwtHandler $jwtHandler;
    private TrustNetworks $networks;
    private array $trustedIssuers;
    private ?string $ebsiTrustRegistry;
    private ?string $cacheDir;

    /**
     * @param string|false|null $cacheDir Cache directory: null resolves
     *        <datadir>/oid4vp_cache from the SSP config, false disables
     *        caching (used in tests), a string uses that path directly.
     */
    public function __construct(
        array $trustedIssuers = [],
        ?string $ebsiTrustRegistry = null,
        ?Client $httpClient = null,
        array $trustNetworks = [],
        string|false|null $cacheDir = null
    ) {
        $this->trustedIssuers = $trustedIssuers;
        $this->ebsiTrustRegistry = $ebsiTrustRegistry;
        $this->httpClient = $httpClient ?? new Client(['timeout' => 10]);
        $this->jwtHandler = new JwtHandler();
        $this->networks = new TrustNetworks($trustNetworks);
        $this->cacheDir = $cacheDir === false ? null : $this->initCacheDir($cacheDir);
    }

    /**
     * Resolve a DID (possibly with #fragment) to a public key for JWT verification.
     *
     * @param string $kid DID with optional #fragment (e.g., "did:blue:z...#key-1")
     * @return Key Public key for JWT verification
     * @throws VerificationException
     */
    public function resolvePublicKey(string $kid): Key
    {
        $did = explode('#', $kid)[0];

        if (str_starts_with($did, 'did:key:')) {
            return $this->jwtHandler->extractPublicKeyFromDid($kid);
        }

        if (str_starts_with($did, 'did:jwk:')) {
            return $this->resolveDidJwk($did);
        }

        if (str_starts_with($did, 'did:web:')) {
            $fragment = $this->fragmentOf($kid);
            return $this->extractKeyFromDidDocument($this->resolveDidWeb($did), $fragment);
        }

        $network = $this->networks->forDid($did);
        if ($network !== null) {
            $fragment = $this->fragmentOf($kid);
            return $this->extractKeyFromDidDocument($this->resolveDidViaRegistry($did, $network), $fragment);
        }

        // Fallback: Universal Resolver (development/testing only)
        return $this->resolveViaUniversalResolver($kid);
    }

    /**
     * Verify that a VC issuer is trusted.
     *
     * @throws VerificationException if issuer is not trusted
     */
    public function verifyIssuerTrust(string $issuerDid): void
    {
        // 1. Static list
        if (in_array($issuerDid, $this->trustedIssuers, true)) {
            return;
        }

        // 2. The issuer's network TIR (EBSI, BLUE, ...)
        $network = $this->networks->forDid($issuerDid);
        if ($network !== null) {
            if ($this->checkNetworkTir($issuerDid, $network)) {
                return;
            }
            throw new VerificationException(
                'VC issuer is not registered in the ' . $network['name']
                . ' Trusted Issuers Registry: ' . $issuerDid
            );
        }

        // 3. Legacy single-URL registry (ebsi_trust_registry option)
        if ($this->ebsiTrustRegistry !== null) {
            if ($this->checkTirUrl($this->ebsiTrustRegistry, $issuerDid)) {
                return;
            }
        }

        // 4. Development mode: no trust source applies to this DID method
        if (empty($this->trustedIssuers) && $this->ebsiTrustRegistry === null) {
            Logger::warning(
                'OID4VP: No trust source configured for issuer DID method. '
                . 'Accepting issuer without trust verification: ' . $issuerDid
            );
            return;
        }

        throw new VerificationException('VC issuer is not trusted: ' . $issuerDid);
    }

    // ─── DID resolution ─────────────────────────────────────────────────

    /**
     * Resolve a did:jwk DID locally by decoding the JWK from the DID string.
     */
    private function resolveDidJwk(string $did): Key
    {
        $jwkPart = substr($did, strlen('did:jwk:'));
        $json = base64_decode(strtr($jwkPart, '-_', '+/'), true);
        if ($json === false) {
            throw new VerificationException('Invalid did:jwk base64url encoding');
        }

        $jwk = json_decode($json, true);
        if (!is_array($jwk)) {
            throw new VerificationException('Invalid did:jwk JWK payload');
        }

        if (($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') {
            throw new VerificationException(
                'Unsupported did:jwk key type (only EC P-256/ES256 supported)'
            );
        }

        return JWK::parseKey($jwk, 'ES256');
    }

    /**
     * Resolve a did:web DID by fetching the DID document over HTTPS
     * (W3C did:web method specification).
     *
     * did:web:example.org           → https://example.org/.well-known/did.json
     * did:web:example.org:path:to   → https://example.org/path/to/did.json
     */
    private function resolveDidWeb(string $did): array
    {
        if (($cached = $this->cacheGet('did_' . $did)) !== null) {
            return $cached;
        }

        $methodSpecificId = substr($did, strlen('did:web:'));
        $parts = explode(':', $methodSpecificId);
        $domain = rawurldecode($parts[0]);
        $pathSegments = array_slice($parts, 1);

        $url = $pathSegments === []
            ? 'https://' . $domain . '/.well-known/did.json'
            : 'https://' . $domain . '/' . implode('/', $pathSegments) . '/did.json';

        [$status, $doc] = $this->httpGetJson($url, 'application/did+ld+json, application/json');
        if ($status !== 200 || !is_array($doc)) {
            throw new VerificationException('did:web resolution failed (' . $status . '): ' . $url);
        }

        // The document must be about the DID we asked for
        if (($doc['id'] ?? null) !== $did) {
            throw new VerificationException(
                'did:web DID document ID mismatch: expected ' . $did . ', got ' . ($doc['id'] ?? 'none')
            );
        }

        $this->cacheSet('did_' . $did, $doc);
        return $doc;
    }

    /**
     * Resolve a DID via its network's DID Registry with the retry chain:
     * primary → fallback mirror (network error) → alternates (404).
     */
    private function resolveDidViaRegistry(string $did, array $network): array
    {
        if (($cached = $this->cacheGet('did_' . $did)) !== null) {
            return $cached;
        }

        $name = $network['name'];
        $encodedDid = rawurlencode($did);
        $accept = 'application/did+ld+json, application/did+json, application/json';
        $notFound = false;

        // Step 1: primary
        try {
            $url = $network['config']['did_registry_url'] . '/identifiers/' . $encodedDid;
            [$status, $doc] = $this->httpGetJson($url, $accept);
            if ($status === 200 && is_array($doc)) {
                $this->cacheSet('did_' . $did, $doc);
                return $doc;
            }
            $notFound = ($status === 404);
        } catch (VerificationException $e) {
            // Network error — step 2: fallback mirror
            $fallbackUrl = $network['config']['fallback_did_registry_url'] ?? null;
            if ($fallbackUrl === null) {
                throw $e;
            }
            Logger::info('OID4VP: [' . $name . '] primary DID registry failed, trying fallback');
            [$status, $doc] = $this->httpGetJson($fallbackUrl . '/identifiers/' . $encodedDid, $accept);
            if ($status === 200 && is_array($doc)) {
                $this->cacheSet('did_' . $did, $doc);
                return $doc;
            }
            $notFound = ($status === 404);
        }

        // Step 3: alternates, only on 404
        if ($notFound) {
            foreach ($network['alternate_configs'] ?? [] as $alt) {
                $label = $alt['label'] ?? 'alternate';
                Logger::info('OID4VP: [' . $name . '] DID not found, trying ' . $label);
                [$status, $doc] = $this->httpGetJson(
                    $alt['did_registry_url'] . '/identifiers/' . $encodedDid,
                    $accept
                );
                if ($status === 200 && is_array($doc)) {
                    $this->cacheSet('did_' . $did, $doc);
                    return $doc;
                }
                if ($status !== 404) {
                    break;
                }
            }
        }

        throw new VerificationException('[' . $name . '] DID not found in any registry: ' . $did);
    }

    /**
     * Fallback: resolve DID via Universal Resolver (development/testing).
     */
    private function resolveViaUniversalResolver(string $kid): Key
    {
        $did = explode('#', $kid)[0];
        $fragment = $this->fragmentOf($kid);

        [$status, $result] = $this->httpGetJson(
            'https://dev.uniresolver.io/1.0/identifiers/' . rawurlencode($did),
            'application/json'
        );

        $didDocument = $result['didDocument'] ?? null;
        if ($status !== 200 || $didDocument === null) {
            throw new VerificationException('Universal Resolver returned no DID document for ' . $did);
        }

        return $this->extractKeyFromDidDocument($didDocument, $fragment);
    }

    // ─── Trusted Issuers Registry ───────────────────────────────────────

    /**
     * Check the issuer against the network's TIR with the retry chain:
     * primary → fallback mirror (network error) → alternates (404).
     */
    private function checkNetworkTir(string $issuerDid, array $network): bool
    {
        $cacheKey = 'tir_' . $issuerDid;
        if (($cached = $this->cacheGet($cacheKey)) !== null) {
            return $cached['trusted'] === true;
        }

        $name = $network['name'];
        $notFound = false;

        // Step 1: primary
        try {
            $trusted = $this->checkTirUrl($network['config']['trusted_issuers_registry_url'], $issuerDid, $notFound);
            if ($trusted) {
                $this->cacheSet($cacheKey, ['trusted' => true]);
                return true;
            }
        } catch (VerificationException) {
            // Network error — step 2: fallback mirror
            $fallbackUrl = $network['config']['fallback_trusted_issuers_registry_url'] ?? null;
            if ($fallbackUrl === null) {
                Logger::warning('OID4VP: [' . $name . '] TIR unreachable for ' . $issuerDid);
                return false;
            }
            Logger::info('OID4VP: [' . $name . '] primary TIR failed, trying fallback');
            try {
                if ($this->checkTirUrl($fallbackUrl, $issuerDid, $notFound)) {
                    $this->cacheSet($cacheKey, ['trusted' => true]);
                    return true;
                }
            } catch (VerificationException) {
                Logger::warning('OID4VP: [' . $name . '] TIR unreachable (primary and fallback) for ' . $issuerDid);
                return false;
            }
        }

        // Step 3: alternates, only on 404
        if ($notFound) {
            foreach ($network['alternate_configs'] ?? [] as $alt) {
                $label = $alt['label'] ?? 'alternate';
                Logger::info('OID4VP: [' . $name . '] issuer not in TIR, trying ' . $label);
                try {
                    if ($this->checkTirUrl($alt['trusted_issuers_registry_url'], $issuerDid, $altNotFound)) {
                        $this->cacheSet($cacheKey, ['trusted' => true]);
                        return true;
                    }
                    if (!$altNotFound) {
                        break;
                    }
                } catch (VerificationException) {
                    break;
                }
            }
        }

        // Definitive "not registered" — cache the negative result too
        $this->cacheSet($cacheKey, ['trusted' => false]);
        return false;
    }

    /**
     * Check a single TIR base URL for an issuer.
     *
     * @param bool|null $notFound Set to true when the registry answered 404
     * @return bool True if the issuer is registered
     * @throws VerificationException on network error
     */
    private function checkTirUrl(string $tirBaseUrl, string $issuerDid, ?bool &$notFound = null): bool
    {
        $notFound = false;
        $url = rtrim($tirBaseUrl, '/') . '/issuers/' . rawurlencode($issuerDid);

        try {
            $response = $this->httpClient->get($url, [
                'headers' => ['Accept' => 'application/json'],
            ]);
            $body = json_decode((string) $response->getBody(), true);
            return isset($body['did']) && $body['did'] === $issuerDid;
        } catch (BadResponseException $e) {
            if ($e->getResponse()->getStatusCode() === 404) {
                $notFound = true;
                return false;
            }
            Logger::warning('OID4VP: TIR error for ' . $issuerDid . ': ' . $e->getMessage());
            return false;
        } catch (GuzzleException $e) {
            throw new VerificationException('TIR unreachable: ' . $e->getMessage());
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private function fragmentOf(string $kid): ?string
    {
        return str_contains($kid, '#') ? explode('#', $kid)[1] : null;
    }

    /**
     * HTTP GET returning [statusCode, decodedJson|null].
     * 4xx/5xx responses are returned as status codes; connection-level
     * failures throw VerificationException (the "network error" signal
     * used by the fallback chains).
     *
     * @return array{0: int, 1: ?array}
     * @throws VerificationException on network error
     */
    private function httpGetJson(string $url, string $accept): array
    {
        try {
            $response = $this->httpClient->get($url, [
                'headers' => ['Accept' => $accept],
            ]);
            return [$response->getStatusCode(), json_decode((string) $response->getBody(), true)];
        } catch (BadResponseException $e) {
            return [$e->getResponse()->getStatusCode(), null];
        } catch (GuzzleException $e) {
            throw new VerificationException('Request failed for ' . $url . ': ' . $e->getMessage());
        }
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
                $jwk = $vm['publicKeyJwk'];
                if (($jwk['kty'] ?? null) === 'EC' && ($jwk['crv'] ?? null) === 'P-256') {
                    return JWK::parseKey($jwk, 'ES256');
                }
            }
        }

        // Retry without the fragment filter: some documents use key IDs that
        // do not match the JWT kid fragment exactly
        if ($fragment !== null) {
            return $this->extractKeyFromDidDocument($didDocument, null);
        }

        throw new VerificationException('No suitable P-256 verification method found in DID document');
    }

    // ─── Disk cache (best-effort) ───────────────────────────────────────

    private function initCacheDir(?string $explicitDir): ?string
    {
        try {
            if ($explicitDir === null) {
                $baseDir = \SimpleSAML\Configuration::getInstance()->getOptionalString(
                    'datadir',
                    dirname(__DIR__, 2) . '/data'
                );
                $explicitDir = rtrim($baseDir, '/') . '/oid4vp_cache';
            }
            if (!is_dir($explicitDir) && !@mkdir($explicitDir, 0700, true) && !is_dir($explicitDir)) {
                return null;
            }
            return $explicitDir;
        } catch (\Exception) {
            // No SSP configuration available — disable cache
            return null;
        }
    }

    private function cachePath(string $key): string
    {
        return $this->cacheDir . '/' . hash('sha256', $key) . '.json';
    }

    private function cacheGet(string $key): ?array
    {
        if ($this->cacheDir === null) {
            return null;
        }
        $path = $this->cachePath($key);
        if (!file_exists($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $entry = json_decode($raw, true);
        if (!is_array($entry) || ($entry['expires'] ?? 0) < time()) {
            @unlink($path);
            return null;
        }
        return $entry['data'] ?? null;
    }

    private function cacheSet(string $key, array $data): void
    {
        if ($this->cacheDir === null) {
            return;
        }
        @file_put_contents(
            $this->cachePath($key),
            json_encode(['expires' => time() + self::CACHE_TTL, 'data' => $data]),
            LOCK_EX
        );
    }
}
