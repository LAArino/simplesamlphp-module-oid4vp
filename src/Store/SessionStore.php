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

namespace SimpleSAML\Module\oid4vp\Store;

use Ramsey\Uuid\Uuid;
use SimpleSAML\Logger;

/**
 * File-based session store for OID4VP challenge sessions.
 *
 * This store bridges the browser (which has the SSP cookie) and the wallet
 * (which is a separate HTTP client with no SSP session). Neither PHP sessions
 * nor SimpleSAML\Session can be used because the wallet cannot access them.
 *
 * Sessions are stored as JSON files in data/oid4vp_sessions/ with flock()
 * for concurrency safety. If SimpleSAML\Store\StoreFactory returns a SQL
 * store, that is used instead (prefixed with 'oid4vp:' to avoid collisions).
 */
class SessionStore
{
    private const STORE_TYPE = 'oid4vp:sessions';

    private int $timeout;
    private ?string $dataDir;
    private ?\SimpleSAML\Store\StoreInterface $sqlStore;

    public function __construct(int $timeout = 300)
    {
        $this->timeout = $timeout;
        $this->sqlStore = null;
        $this->dataDir = null;

        // Try SQL store first (if configured in SimpleSAMLphp)
        try {
            $config = \SimpleSAML\Configuration::getInstance();
            $storeType = $config->getOptionalString('store.type', 'phpsession');
            if ($storeType !== 'phpsession') {
                $store = \SimpleSAML\Store\StoreFactory::getInstance($storeType);
                if ($store instanceof \SimpleSAML\Store\StoreInterface) {
                    $this->sqlStore = $store;
                    return;
                }
            }
        } catch (\Exception $e) {
            // Fall through to file-based
        }

        // File-based storage in the module's data directory
        $baseDir = \SimpleSAML\Configuration::getInstance()->getOptionalString(
            'datadir',
            dirname(__DIR__, 3) . '/data'
        );
        $this->dataDir = rtrim($baseDir, '/') . '/oid4vp_sessions';

        if (!is_dir($this->dataDir)) {
            if (!mkdir($this->dataDir, 0700, true) && !is_dir($this->dataDir)) {
                throw new \RuntimeException('Cannot create session directory: ' . $this->dataDir);
            }
        }
    }

    /**
     * Create a new OID4VP session.
     *
     * @param string $authState The SimpleSAMLphp Auth\State ID
     * @param array $verifierConfig Verifier config to store (wallet endpoints read this instead of Auth\State)
     * @return array{session_id: string, nonce: string, state: string}
     */
    public function create(string $authState, array $verifierConfig = []): array
    {
        $sessionId = Uuid::uuid4()->toString();
        $nonce = $this->generateNonce();
        $state = $this->generateNonce();

        $data = [
            'session_id' => $sessionId,
            'nonce' => $nonce,
            'state' => $state,
            'auth_state' => $authState,
            'verifier_config' => $verifierConfig,
            'status' => 'pending',
            'attributes' => null,
            'created_at' => time(),
        ];

        if ($this->sqlStore !== null) {
            $expiry = time() + $this->timeout;
            $this->sqlStore->set(self::STORE_TYPE, $sessionId, $data, $expiry);
            // Reverse index: state → session_id
            $this->sqlStore->set(self::STORE_TYPE . ':state', $state, $sessionId, $expiry);
        } else {
            $this->writeFile($sessionId, $data);
            // Reverse index: state → session_id (small file mapping)
            $this->writeFile('state_' . hash('sha256', $state), ['session_id' => $sessionId]);
        }

        return [
            'session_id' => $sessionId,
            'nonce' => $nonce,
            'state' => $state,
        ];
    }

    /**
     * Retrieve a session by its ID.
     */
    public function get(string $sessionId): ?array
    {
        if ($this->sqlStore !== null) {
            $data = $this->sqlStore->get(self::STORE_TYPE, $sessionId);
            if ($data === null) {
                return null;
            }
            return $this->checkExpiry($data, $sessionId);
        }

        $data = $this->readFile($sessionId);
        if ($data === null) {
            return null;
        }
        return $this->checkExpiry($data, $sessionId);
    }

    /**
     * Find a session by its state parameter (used by direct_post from wallet).
     */
    public function getByState(string $state): ?array
    {
        if ($this->sqlStore !== null) {
            $sessionId = $this->sqlStore->get(self::STORE_TYPE . ':state', $state);
            if ($sessionId === null) {
                return null;
            }
            return $this->get($sessionId);
        }

        // Look up state → session_id via reverse index file
        $index = $this->readFile('state_' . hash('sha256', $state));
        if ($index === null || !isset($index['session_id'])) {
            return null;
        }
        return $this->get($index['session_id']);
    }

    /**
     * Mark a session as completed and store the credential attributes.
     */
    public function complete(string $sessionId, array $attributes): bool
    {
        $data = $this->get($sessionId);
        if ($data === null) {
            return false;
        }

        // Prevent double submission
        if ($data['status'] !== 'pending') {
            return false;
        }

        $data['status'] = 'completed';
        $data['attributes'] = $attributes;

        if ($this->sqlStore !== null) {
            $this->sqlStore->set(self::STORE_TYPE, $sessionId, $data, time() + $this->timeout);
        } else {
            $this->writeFile($sessionId, $data);
        }

        return true;
    }

    /**
     * Delete a session and its state index.
     */
    public function delete(string $sessionId): void
    {
        if ($this->sqlStore !== null) {
            // Try to clean up the state index too
            $data = $this->sqlStore->get(self::STORE_TYPE, $sessionId);
            if ($data !== null && isset($data['state'])) {
                $this->sqlStore->delete(self::STORE_TYPE . ':state', $data['state']);
            }
            $this->sqlStore->delete(self::STORE_TYPE, $sessionId);
            return;
        }

        // File-based: read to get state for index cleanup
        $data = $this->readFile($sessionId);
        if ($data !== null && isset($data['state'])) {
            $this->deleteFile('state_' . hash('sha256', $data['state']));
        }
        $this->deleteFile($sessionId);
    }

    /**
     * Remove expired sessions (housekeeping).
     */
    public function cleanup(): void
    {
        if ($this->sqlStore !== null) {
            // SQL store handles TTL-based expiry automatically
            return;
        }

        if ($this->dataDir === null) {
            return;
        }

        $files = glob($this->dataDir . '/*.json');
        if ($files === false) {
            return;
        }

        $cutoff = time() - $this->timeout;
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff) {
                @unlink($file);
            }
        }
    }

    /**
     * Check if session has expired and delete if so.
     */
    private function checkExpiry(array $data, string $sessionId): ?array
    {
        if (isset($data['created_at']) && (time() - $data['created_at']) > $this->timeout) {
            $this->delete($sessionId);
            return null;
        }
        return $data;
    }

    /**
     * Write session data to a JSON file with exclusive lock.
     */
    private function writeFile(string $key, array $data): void
    {
        $path = $this->dataDir . '/' . $this->sanitizeKey($key) . '.json';
        $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $fp = fopen($path, 'c');
        if ($fp === false) {
            throw new \RuntimeException('Cannot open session file: ' . $path);
        }

        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            throw new \RuntimeException('Cannot lock session file: ' . $path);
        }

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $json);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        chmod($path, 0600);
    }

    /**
     * Read session data from a JSON file with shared lock.
     */
    private function readFile(string $key): ?array
    {
        $path = $this->dataDir . '/' . $this->sanitizeKey($key) . '.json';
        if (!file_exists($path)) {
            return null;
        }

        $fp = fopen($path, 'r');
        if ($fp === false) {
            return null;
        }

        if (!flock($fp, LOCK_SH)) {
            fclose($fp);
            return null;
        }

        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        if ($content === false || $content === '') {
            return null;
        }

        $data = json_decode($content, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Delete a session file.
     */
    private function deleteFile(string $key): void
    {
        $path = $this->dataDir . '/' . $this->sanitizeKey($key) . '.json';
        if (file_exists($path)) {
            @unlink($path);
        }
    }

    /**
     * Sanitize a key for use as a filename.
     */
    private function sanitizeKey(string $key): string
    {
        return preg_replace('/[^a-zA-Z0-9_-]/', '_', $key);
    }

    /**
     * Generate a cryptographic nonce (32 bytes, base64url-encoded).
     */
    private function generateNonce(): string
    {
        $bytes = random_bytes(32);
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
