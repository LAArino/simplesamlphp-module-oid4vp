<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oid4vp\Crypto;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oid4vp\Crypto\JwtHandler;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;

class JwtHandlerTest extends TestCase
{
    public function testDecodeHeaderValidJwt(): void
    {
        $handler = new JwtHandler();

        $header = rtrim(strtr(base64_encode(json_encode([
            'alg' => 'ES256',
            'typ' => 'JWT',
            'kid' => 'did:key:z123',
        ])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'test'])), '+/', '-_'), '=');
        $jwt = $header . '.' . $payload . '.signature';

        $result = $handler->decodeHeader($jwt);

        $this->assertSame('ES256', $result['alg']);
        $this->assertSame('did:key:z123', $result['kid']);
    }

    public function testDecodeHeaderInvalidFormat(): void
    {
        $handler = new JwtHandler();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Invalid JWT format');

        $handler->decodeHeader('not.a.valid.jwt.too.many.parts');
    }

    public function testDecodeHeaderInvalidBase64(): void
    {
        $handler = new JwtHandler();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Invalid JWT header');

        $handler->decodeHeader('!!!invalid!!!.payload.sig');
    }

    public function testExtractPublicKeyFromDidUnsupportedMethod(): void
    {
        $handler = new JwtHandler();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Unsupported DID method');

        $handler->extractPublicKeyFromDid('did:web:example.com');
    }

    public function testExtractPublicKeyFromDidKeyInvalidMultibase(): void
    {
        $handler = new JwtHandler();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Unsupported did:key multibase');

        $handler->extractPublicKeyFromDid('did:key:m123456');
    }

    public function testClassHasExpectedMethods(): void
    {
        $reflection = new \ReflectionClass(JwtHandler::class);

        $this->assertTrue($reflection->hasMethod('createAuthorizationRequest'));
        $this->assertTrue($reflection->hasMethod('verifyJwt'));
        $this->assertTrue($reflection->hasMethod('decodeHeader'));
        $this->assertTrue($reflection->hasMethod('extractPublicKeyFromDid'));
        $this->assertTrue($reflection->hasMethod('loadPrivateKeyFromFile'));
    }
}
