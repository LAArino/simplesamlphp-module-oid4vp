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

    /** Byte-wise base58 encode — the inverse of JwtHandler's decoder, no ext-gmp. */
    private function base58Encode(string $data): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        $digits = [];
        foreach (unpack('C*', $data) as $byte) {
            $carry = $byte;
            for ($i = count($digits) - 1; $i >= 0; $i--) {
                $carry += $digits[$i] << 8;
                $digits[$i] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
            while ($carry > 0) {
                array_unshift($digits, $carry % 58);
                $carry = intdiv($carry, 58);
            }
        }

        $encoded = '';
        foreach ($digits as $digit) {
            $encoded .= $alphabet[$digit];
        }

        for ($i = 0; $i < strlen($data) && $data[$i] === "\x00"; $i++) {
            $encoded = '1' . $encoded;
        }

        return $encoded;
    }

    /**
     * The decoder must handle a real P-256 did:key (multicodec 0x1200) and
     * preserve leading zero bytes, without ext-gmp being loaded.
     */
    public function testBase58DecodeHandlesStandardDidKey(): void
    {
        $handler = new JwtHandler();

        $res = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $details = openssl_pkey_get_details($res);
        $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

        // Compressed point: 0x02/0x03 prefix by Y parity, then X
        $compressed = chr((ord($y[31]) & 1) === 0 ? 0x02 : 0x03) . $x;
        $did = 'did:key:z' . $this->base58Encode("\x80\x24" . $compressed);

        $key = $handler->extractPublicKeyFromDid($did);

        $this->assertInstanceOf(\Firebase\JWT\Key::class, $key);
    }

    public function testBase58DecodeRejectsInvalidCharacters(): void
    {
        $handler = new JwtHandler();

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Invalid did:key base58 encoding');

        // '0', 'O', 'I' and 'l' are excluded from the base58 alphabet
        $handler->extractPublicKeyFromDid('did:key:z0OIl0OIl0OIl');
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
