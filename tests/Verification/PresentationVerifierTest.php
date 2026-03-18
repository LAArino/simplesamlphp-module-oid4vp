<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oid4vp\Verification;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oid4vp\Verification\PresentationVerifier;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;

/**
 * Unit tests for PresentationVerifier.
 *
 * Tests JWT parsing, algorithm validation, and header checks.
 * Full VP/VC verification requires mock DID resolution.
 */
class PresentationVerifierTest extends TestCase
{
    private string $verifierId = 'https://idp.example.org';

    public function testInvalidJwtFormatThrows(): void
    {
        $verifier = new PresentationVerifier($this->verifierId);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Invalid JWT format');

        $verifier->verify('not-a-jwt', 'test-nonce');
    }

    public function testInvalidJwtHeaderThrows(): void
    {
        $verifier = new PresentationVerifier($this->verifierId);

        $this->expectException(VerificationException::class);
        $verifier->verify('!!!.payload.signature', 'test-nonce');
    }

    public function testWrongAlgorithmThrows(): void
    {
        $verifier = new PresentationVerifier($this->verifierId);

        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['nonce' => 'test'])), '+/', '-_'), '=');
        $jwt = $header . '.' . $payload . '.fake-signature';

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('VP JWT must use ES256 algorithm');

        $verifier->verify($jwt, 'test-nonce');
    }

    public function testMissingKidThrows(): void
    {
        $verifier = new PresentationVerifier($this->verifierId);

        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['nonce' => 'test'])), '+/', '-_'), '=');
        $jwt = $header . '.' . $payload . '.fake-signature';

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('VP JWT header missing kid');

        $verifier->verify($jwt, 'test-nonce');
    }

    public function testConstructorWithAllOptions(): void
    {
        $verifier = new PresentationVerifier(
            'https://idp.example.org',
            ['did:ebsi:issuer1', 'did:ebsi:issuer2'],
            'https://api-pilot.ebsi.eu/trusted-issuers-registry/v5',
            new \GuzzleHttp\Client(['timeout' => 5])
        );

        $this->assertInstanceOf(PresentationVerifier::class, $verifier);
    }
}
