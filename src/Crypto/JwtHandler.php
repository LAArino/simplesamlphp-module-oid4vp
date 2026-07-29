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

namespace SimpleSAML\Module\oid4vp\Crypto;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use SimpleSAML\Error;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;

/**
 * Handles JWT operations for OID4VP:
 *   - Create signed JWT Authorization Requests (JAR) with ES256
 *   - Verify JWT VP and VC tokens
 *   - Resolve did:key to public key PEM (day 1), did:ebsi (future)
 */
class JwtHandler
{
    /**
     * Create a signed JWT Authorization Request (JAR) for OID4VP.
     *
     * @param array $claims JWT claims (iss, aud, response_type, nonce, state, presentation_definition, etc.)
     * @param string $privateKeyPem PEM-encoded ES256 private key
     * @param string|null $kid Key ID for the JWT header
     * @return string Signed JWT
     */
    public function createAuthorizationRequest(array $claims, string $privateKeyPem, ?string $kid = null): string
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new Error\Exception('OID4VP: Failed to load ES256 private key: ' . openssl_error_string());
        }

        $defaults = [
            'iat' => time(),
            'exp' => time() + 300,
        ];
        $payload = array_merge($defaults, $claims);

        $head = [];
        if ($kid !== null) {
            $head['kid'] = $kid;
        }

        return JWT::encode($payload, $key, 'ES256', null, $head);
    }

    /**
     * Verify a JWT (VP or VC) using a public key.
     *
     * @param string $jwt The JWT to verify
     * @param Key $publicKey The public key for verification
     * @return array The decoded payload as associative array
     * @throws VerificationException
     */
    public function verifyJwt(string $jwt, Key $publicKey): array
    {
        try {
            $decoded = JWT::decode($jwt, $publicKey);
            return json_decode(json_encode($decoded), true);
        } catch (\Exception $e) {
            throw new VerificationException('JWT verification failed: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JWT header without signature verification.
     *
     * @return array The decoded header
     * @throws VerificationException
     */
    public function decodeHeader(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new VerificationException('Invalid JWT format');
        }

        $header = json_decode(
            base64_decode(strtr($parts[0], '-_', '+/')),
            true
        );

        if ($header === null) {
            throw new VerificationException('Invalid JWT header');
        }

        return $header;
    }

    /**
     * Extract a public key from a DID.
     *
     * Day 1: supports did:key (key embedded in DID via multibase/multicodec).
     * Future: did:ebsi via EBSI DID Registry.
     *
     * @param string $did The DID (possibly with #fragment)
     * @return Key The public key for JWT verification
     * @throws VerificationException
     */
    public function extractPublicKeyFromDid(string $did): Key
    {
        $baseDid = explode('#', $did)[0];

        if (str_starts_with($baseDid, 'did:key:')) {
            return $this->resolveDidKey($baseDid);
        }

        throw new VerificationException(
            'Unsupported DID method: ' . $baseDid
            . '. Only did:key is supported (day 1). did:ebsi support planned.'
        );
    }

    /**
     * Resolve did:key — the public key is embedded in the DID itself.
     *
     * Two multicodec encodings are supported:
     *   0x1200 (varint 0x80 0x24) — compressed P-256 public key (standard did:key)
     *   0xeb51 (varint 0xD1 0xD6 0x03) — jwk_jcs-pub: JCS-canonicalized JWK
     *     as UTF-8 JSON (EBSI natural-person did:key format)
     *
     * The key is base58btc-encoded with 'z' prefix (multibase).
     */
    private function resolveDidKey(string $did): Key
    {
        $multibase = substr($did, strlen('did:key:'));

        if (!str_starts_with($multibase, 'z')) {
            throw new VerificationException('Unsupported did:key multibase encoding (expected z/base58btc)');
        }

        $decoded = $this->base58Decode(substr($multibase, 1));
        if ($decoded === false || strlen($decoded) < 3) {
            throw new VerificationException('Invalid did:key base58 encoding');
        }

        // Check multicodec varint prefix for P-256 (0x1200 → varint 0x80 0x24)
        $prefix = unpack('C3', $decoded);
        if ($prefix[1] === 0x80 && $prefix[2] === 0x24) {
            // P-256 compressed public key (33 bytes after 2-byte prefix)
            $compressedKey = substr($decoded, 2);
            if (strlen($compressedKey) !== 33) {
                throw new VerificationException('Invalid P-256 compressed key length: ' . strlen($compressedKey));
            }
            $jwk = $this->compressedP256ToJwk($compressedKey);
            return JWK::parseKey($jwk, 'ES256');
        }

        // jwk_jcs-pub (0xeb51 → varint 0xD1 0xD6 0x03): EBSI did:key format
        if ($prefix[1] === 0xd1 && $prefix[2] === 0xd6 && $prefix[3] === 0x03) {
            return $this->jwkJcsPubToKey(substr($decoded, 3));
        }

        throw new VerificationException('Unsupported did:key curve (only P-256/ES256 supported)');
    }

    /**
     * Parse a jwk_jcs-pub payload (JCS-canonicalized JWK as UTF-8 JSON) into a Key.
     */
    private function jwkJcsPubToKey(string $jwkJson): Key
    {
        $jwk = json_decode($jwkJson, true);
        if (!is_array($jwk)) {
            throw new VerificationException('Invalid jwk_jcs-pub did:key: malformed JWK JSON');
        }

        if (($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') {
            throw new VerificationException(
                'Unsupported jwk_jcs-pub key type (only EC P-256/ES256 supported)'
            );
        }

        return JWK::parseKey($jwk, 'ES256');
    }

    /**
     * Convert a compressed P-256 public key to JWK format.
     *
     * Uses OpenSSL to decompress the point (compute Y from X).
     */
    private function compressedP256ToJwk(string $compressedKey): array
    {
        $prefix = ord($compressedKey[0]);
        if ($prefix !== 0x02 && $prefix !== 0x03) {
            throw new VerificationException('Invalid compressed key prefix: 0x' . dechex($prefix));
        }

        // Build a DER-encoded EC public key with the compressed point
        // ASN.1: SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING { compressed point } }
        $ecOid = hex2bin('06072a8648ce3d0201');       // OID 1.2.840.10045.2.1 (ecPublicKey)
        $p256Oid = hex2bin('06082a8648ce3d030107');    // OID 1.2.840.10045.3.1.7 (prime256v1)
        $algSequence = chr(0x30) . chr(strlen($ecOid . $p256Oid)) . $ecOid . $p256Oid;

        // BIT STRING wrapping the compressed point (prefixed with 0x00 unused bits)
        $bitString = chr(0x03) . chr(strlen($compressedKey) + 1) . chr(0x00) . $compressedKey;

        $derBody = $algSequence . $bitString;
        $der = chr(0x30) . chr(strlen($derBody)) . $derBody;

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----";

        $keyResource = openssl_pkey_get_public($pem);
        if ($keyResource === false) {
            throw new VerificationException('Failed to decompress P-256 key via OpenSSL');
        }

        $details = openssl_pkey_get_details($keyResource);
        $x = $details['ec']['x'] ?? null;
        $y = $details['ec']['y'] ?? null;

        if ($x === null || $y === null) {
            throw new VerificationException('Failed to extract P-256 coordinates from decompressed key');
        }

        return [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => rtrim(strtr(base64_encode($x), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode($y), '+/', '-_'), '='),
        ];
    }

    /**
     * Base58 decode (Bitcoin alphabet).
     *
     * Uses byte-wise base conversion with carry propagation rather than a
     * bignum library, so the module has no ext-gmp/ext-bcmath requirement —
     * several SimpleSAMLphp container images ship neither. Inputs are DID
     * fragments of a few dozen bytes, where the quadratic cost is irrelevant.
     */
    private function base58Decode(string $input): string|false
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        $bytes = [];
        for ($i = 0; $i < strlen($input); $i++) {
            $value = strpos($alphabet, $input[$i]);
            if ($value === false) {
                return false;
            }

            // bytes = bytes * 58 + value, big-endian, carrying upwards
            $carry = $value;
            for ($j = count($bytes) - 1; $j >= 0; $j--) {
                $carry += $bytes[$j] * 58;
                $bytes[$j] = $carry & 0xff;
                $carry >>= 8;
            }
            while ($carry > 0) {
                array_unshift($bytes, $carry & 0xff);
                $carry >>= 8;
            }
        }

        // Leading '1's encode leading zero bytes
        for ($i = 0; $i < strlen($input) && $input[$i] === '1'; $i++) {
            array_unshift($bytes, 0);
        }

        return $bytes === [] ? '' : pack('C*', ...$bytes);
    }

    /**
     * Load a private key from a file path.
     *
     * @return string PEM-encoded private key
     */
    public function loadPrivateKeyFromFile(string $keyPath): string
    {
        // Try absolute path first
        if (file_exists($keyPath)) {
            $pem = file_get_contents($keyPath);
        } else {
            // Resolve relative to the SimpleSAMLphp certdir. getPathValue() (not
            // getOptionalString) resolves the configured path against the SSP
            // base directory — 'certdir' is relative by default and the web
            // server's working directory is public/, not the install root.
            $certDir = \SimpleSAML\Configuration::getInstance()->getPathValue('certdir', 'cert/');
            $fullPath = rtrim($certDir, '/') . '/' . basename($keyPath);
            if (!file_exists($fullPath)) {
                throw new Error\Exception('OID4VP: Signing key not found: ' . $keyPath);
            }
            $pem = file_get_contents($fullPath);
        }

        if ($pem === false) {
            throw new Error\Exception('OID4VP: Cannot read signing key: ' . $keyPath);
        }

        return $pem;
    }
}
