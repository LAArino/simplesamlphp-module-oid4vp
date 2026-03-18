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

namespace SimpleSAML\Module\oid4vp\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\oid4vp\Auth\Source\OID4VP;
use SimpleSAML\Module\oid4vp\Crypto\JwtHandler;
use SimpleSAML\Module\oid4vp\Mapping\CredentialMapper;
use SimpleSAML\Module\oid4vp\Store\SessionStore;
use SimpleSAML\Module\oid4vp\Verification\PresentationVerifier;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller for the 4 OID4VP HTTP endpoints.
 *
 *   GET  /qrpage           — Browser: show QR code page (or complete auth if complete=1)
 *   GET  /request_uri/{id} — Wallet: serve signed JWT Authorization Request
 *   POST /direct_post      — Wallet: receive VP token, verify, store result
 *   GET  /status/{id}      — Browser: poll session status (JSON)
 *
 * IMPORTANT: request_uri and direct_post are called by the wallet, which has
 * NO SSP session cookie. These endpoints MUST NOT use Auth\State — they read
 * all config from the file-based SessionStore instead.
 */
class VerifierController
{
    private Configuration $config;

    public function __construct(Configuration $config)
    {
        $this->config = $config;
    }

    /**
     * GET /qrpage — Generate the OID4VP QR page or complete authentication.
     *
     * Without complete=1: generates session, creates QR with openid:// URI, renders template.
     * With complete=1: loads attributes from SessionStore, calls completeAuth().
     *
     * This is the ONLY endpoint that uses Auth\State (browser has SSP cookie).
     */
    public function qrpage(Request $request): Response
    {
        $authStateId = $request->query->get('AuthState');
        if ($authStateId === null) {
            throw new Error\BadRequest('Missing AuthState parameter');
        }

        $state = Auth\State::loadState($authStateId, 'oid4vp:auth');

        // If complete=1, finish authentication with stored attributes
        if ($request->query->get('complete') === '1') {
            return $this->completeAuthentication($state);
        }

        $timeout = $state['oid4vp:session_timeout'] ?? 300;

        // Create a new OID4VP session, storing verifier config for wallet endpoints
        $store = new SessionStore($timeout);
        $verifierConfig = [
            'verifier_id' => $state['oid4vp:verifier_id'],
            'verifier_kid' => $state['oid4vp:verifier_kid'] ?? null,
            'signing_key' => $state['oid4vp:signing_key'],
            'signing_cert' => $state['oid4vp:signing_cert'] ?? null,
            'presentation_definition_type' => $state['oid4vp:presentation_definition_type'] ?? 'VerifiableEducationalID',
            'trusted_issuers' => $state['oid4vp:trusted_issuers'] ?? [],
            'ebsi_trust_registry' => $state['oid4vp:ebsi_trust_registry'] ?? null,
        ];
        $sessionData = $store->create($authStateId, $verifierConfig);

        // Store session_id in auth state for resume
        $state['oid4vp:session_id'] = $sessionData['session_id'];
        $newStateId = Auth\State::saveState($state, 'oid4vp:auth');

        // Build the openid:// URI pointing to our JAR endpoint
        $requestUri = Module::getModuleURL('oid4vp/request_uri/' . $sessionData['session_id']);
        $openidUri = 'openid://?request_uri=' . urlencode($requestUri);

        // URLs for browser JS
        $qrpageUrl = Module::getModuleURL('oid4vp/qrpage');
        $statusUrl = Module::getModuleURL('oid4vp/status/' . $sessionData['session_id']);

        // Render the QR code page
        $t = new Template($this->config, 'oid4vp:qrcode.twig');
        $t->data['openidUri'] = $openidUri;
        $t->data['sessionId'] = $sessionData['session_id'];
        $t->data['statusUrl'] = $statusUrl;
        $t->data['qrpageUrl'] = $qrpageUrl;
        $t->data['authState'] = $newStateId;
        $t->data['timeout'] = $timeout;

        return $t;
    }

    /**
     * GET /request_uri/{id} — Serve the signed JWT Authorization Request (JAR) to the wallet.
     *
     * Content-Type: application/oauth-authz-req+jwt
     *
     * NO Auth\State here — reads config from SessionStore (wallet has no SSP cookie).
     */
    public function requestUri(Request $request, string $sessionId): Response
    {
        $store = new SessionStore();
        $session = $store->get($sessionId);

        if ($session === null) {
            return new JsonResponse(['error' => 'session_not_found'], 404);
        }

        // Read verifier config from the session (stored at creation time by qrpage)
        $vc = $session['verifier_config'] ?? null;
        if ($vc === null) {
            return new JsonResponse(['error' => 'missing_verifier_config'], 500);
        }

        $verifierId = $vc['verifier_id'];
        $signingKey = $vc['signing_key'];
        $presentationType = $vc['presentation_definition_type'] ?? 'VerifiableEducationalID';

        // Build the JWT Authorization Request
        $directPostUrl = Module::getModuleURL('oid4vp/direct_post');

        $claims = [
            'iss' => $verifierId,
            'aud' => 'https://self-issued.me/v2',
            'response_type' => 'vp_token',
            'response_mode' => 'direct_post',
            'response_uri' => $directPostUrl,
            'nonce' => $session['nonce'],
            'state' => $session['state'],
            'presentation_definition' => $this->buildPresentationDefinition($presentationType),
            'iat' => time(),
            'exp' => time() + 300,
        ];

        // Sign the JAR with ES256
        $jwtHandler = new JwtHandler();
        $privateKeyPem = $jwtHandler->loadPrivateKeyFromFile($signingKey);
        $verifierKid = $vc['verifier_kid'] ?? null;
        $jar = $jwtHandler->createAuthorizationRequest($claims, $privateKeyPem, $verifierKid);

        return new Response($jar, 200, [
            'Content-Type' => 'application/oauth-authz-req+jwt',
            'Cache-Control' => 'no-store',
        ]);
    }

    /**
     * POST /direct_post — Receive and verify the VP token from the wallet.
     *
     * The wallet sends: vp_token, presentation_submission, state.
     * The state parameter links back to our session_id via the SessionStore.
     *
     * NO Auth\State here — reads config from SessionStore (wallet has no SSP cookie).
     */
    public function directPost(Request $request): Response
    {
        $vpToken = $request->request->get('vp_token');
        $state = $request->request->get('state');

        if ($vpToken === null || $state === null) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Missing vp_token or state',
            ], 400);
        }

        // Find the session by state (wallet doesn't have SSP cookie — this is the bridge)
        $store = new SessionStore();
        $session = $store->getByState($state);

        if ($session === null) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Unknown or expired state',
            ], 400);
        }

        // Prevent double submission
        if ($session['status'] !== 'pending') {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Session already processed',
            ], 400);
        }

        // Read verifier config from the session (stored at creation time by qrpage)
        $vc = $session['verifier_config'] ?? null;
        if ($vc === null) {
            Logger::error('OID4VP: Missing verifier_config in session');
            return new JsonResponse([
                'error' => 'server_error',
                'error_description' => 'Internal configuration error',
            ], 500);
        }

        $verifierId = $vc['verifier_id'];
        $trustedIssuers = $vc['trusted_issuers'] ?? [];
        $ebsiTrustRegistry = $vc['ebsi_trust_registry'] ?? null;

        // Verify the VP token
        $verifier = new PresentationVerifier(
            $verifierId,
            $trustedIssuers,
            $ebsiTrustRegistry
        );

        try {
            $result = $verifier->verify($vpToken, $session['nonce']);
        } catch (VerificationException $e) {
            Logger::warning('OID4VP: VP verification failed: ' . $e->getMessage());
            return new JsonResponse([
                'error' => 'invalid_presentation',
                'error_description' => $e->getMessage(),
            ], 400);
        }

        // Validate VC type
        $vcTypes = $result['vc_type'] ?? [];
        $requiredType = $vc['presentation_definition_type'] ?? 'VerifiableEducationalID';
        if (!in_array($requiredType, $vcTypes, true)) {
            Logger::warning('OID4VP: VC type mismatch. Expected ' . $requiredType);
            return new JsonResponse([
                'error' => 'invalid_presentation',
                'error_description' => 'VC does not contain required type: ' . $requiredType,
            ], 400);
        }

        // Validate required fields
        $mapper = new CredentialMapper();
        $missing = $mapper->validateRequired($result['credential_subject']);
        if (!empty($missing)) {
            Logger::warning('OID4VP: VC missing required fields: ' . implode(', ', $missing));
            return new JsonResponse([
                'error' => 'invalid_presentation',
                'error_description' => 'VC missing required fields: ' . implode(', ', $missing),
            ], 400);
        }

        // Mark session as completed with credential attributes
        $store->complete($session['session_id'], $result['credential_subject']);

        Logger::info('OID4VP: VP verified successfully for session ' . $session['session_id']);

        return new JsonResponse(['status' => 'ok'], 200);
    }

    /**
     * GET /status/{id} — Poll session status (called by browser JS every 2s).
     */
    public function status(Request $request, string $sessionId): JsonResponse
    {
        $store = new SessionStore();
        $session = $store->get($sessionId);

        if ($session === null) {
            return new JsonResponse(['status' => 'expired'], 200);
        }

        return new JsonResponse(['status' => $session['status']]);
    }

    /**
     * Complete authentication after VP has been verified.
     *
     * Called when browser detects 'completed' status and redirects to qrpage?complete=1.
     * Loads attributes from SessionStore, maps to SAML, calls completeAuth().
     */
    private function completeAuthentication(array $state): never
    {
        $sessionId = $state['oid4vp:session_id'] ?? null;
        if ($sessionId === null) {
            throw new Error\Exception('OID4VP: Missing session_id in state');
        }

        $timeout = $state['oid4vp:session_timeout'] ?? 300;
        $store = new SessionStore($timeout);
        $session = $store->get($sessionId);

        if ($session === null) {
            throw new Error\Exception('OID4VP: Session not found or expired');
        }

        if ($session['status'] !== 'completed') {
            throw new Error\Exception('OID4VP: Session not completed (status: ' . $session['status'] . ')');
        }

        $attributes = $session['attributes'];
        if ($attributes === null || empty($attributes)) {
            throw new Error\Exception('OID4VP: No attributes in completed session');
        }

        // Map credential subject to SAML attributes
        $useOid = $state['oid4vp:use_oid_format'] ?? false;
        $customMap = $state['oid4vp:attribute_map'] ?? [];
        $mapper = new CredentialMapper($useOid, $customMap);
        $samlAttributes = $mapper->map($attributes);

        if (empty($samlAttributes)) {
            throw new Error\Exception('OID4VP: Credential mapping produced no attributes');
        }

        $state['Attributes'] = $samlAttributes;

        // Clean up OID4VP session
        $store->delete($sessionId);

        Logger::info('OID4VP: Authentication completed successfully');

        // Complete SimpleSAMLphp authentication (never returns)
        Auth\Source::completeAuth($state);
    }

    /**
     * Build the OID4VP presentation definition for the requested credential type.
     */
    private function buildPresentationDefinition(string $credentialType): array
    {
        return [
            'id' => 'educationalid-presentation',
            'format' => [
                'jwt_vp' => ['alg' => ['ES256']],
                'jwt_vc' => ['alg' => ['ES256']],
            ],
            'input_descriptors' => [
                [
                    'id' => 'educationalid-descriptor',
                    'format' => [
                        'jwt_vp' => ['alg' => ['ES256']],
                        'jwt_vc' => ['alg' => ['ES256']],
                    ],
                    'constraints' => [
                        'fields' => [
                            [
                                'path' => ['$.vc.type'],
                                'filter' => [
                                    'type' => 'array',
                                    'contains' => ['const' => $credentialType],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }
}
