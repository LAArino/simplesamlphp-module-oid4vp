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

    public function testExtractPublicKeyFromEbsiDidKey(): void
    {
        $handler = new JwtHandler();

        // Build a jwk_jcs-pub did:key (multicodec 0xeb51) from a real P-256 key,
        // mirroring the EBSI natural-person format used by EUDI wallets
        $res = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $details = openssl_pkey_get_details($res);
        $b64u = fn(string $bin) => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');

        // JCS canonical order for P-256 JWK: crv < kty < x < y
        $jcsJwk = sprintf(
            '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}',
            $b64u($details['ec']['x']),
            $b64u($details['ec']['y'])
        );

        $payload = "\xd1\xd6\x03" . $jcsJwk;
        $did = 'did:key:z' . $this->base58Encode($payload);

        $key = $handler->extractPublicKeyFromDid($did);

        $this->assertInstanceOf(\Firebase\JWT\Key::class, $key);
    }

    public function testExtractPublicKeyFromEbsiDidKeyRejectsNonP256(): void
    {
        $handler = new JwtHandler();

        $payload = "\xd1\xd6\x03" . '{"crv":"Ed25519","kty":"OKP","x":"abc"}';
        $did = 'did:key:z' . $this->base58Encode($payload);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('only EC P-256/ES256 supported');

        $handler->extractPublicKeyFromDid($did);
    }

    private function base58Encode(string $data): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $num = gmp_init(bin2hex($data), 16);
        $encoded = '';
        while (gmp_cmp($num, 0) > 0) {
            [$num, $rem] = [gmp_div_q($num, 58), gmp_intval(gmp_mod($num, 58))];
            $encoded = $alphabet[$rem] . $encoded;
        }
        for ($i = 0; $i < strlen($data) && $data[$i] === "\x00"; $i++) {
            $encoded = '1' . $encoded;
        }
        return $encoded;
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
