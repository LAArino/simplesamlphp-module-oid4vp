<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oid4vp\Verification;

use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oid4vp\Lib\VerificationException;
use SimpleSAML\Module\oid4vp\Verification\TrustChainResolver;
use SimpleSAML\Module\oid4vp\Verification\TrustNetworks;

/**
 * Unit tests for TrustChainResolver: multi-network DID resolution
 * (EBSI + BLUE), fallback chains, and issuer trust verification.
 */
class TrustChainResolverTest extends TestCase
{
    /** A valid P-256 public JWK (generated once with openssl). */
    private array $p256Jwk;

    protected function setUp(): void
    {
        $res = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $details = openssl_pkey_get_details($res);
        $this->p256Jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $this->b64u($details['ec']['x']),
            'y' => $this->b64u($details['ec']['y']),
        ];
    }

    private function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private function mockClient(array $queue, ?array &$requests = null): Client
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        if ($requests !== null) {
            $stack->push(function (callable $handler) use (&$requests) {
                return function ($request, array $options) use ($handler, &$requests) {
                    $requests[] = (string) $request->getUri();
                    return $handler($request, $options);
                };
            });
        }
        return new Client(['handler' => $stack]);
    }

    private function didDocumentFor(string $did): array
    {
        return [
            '@context' => 'https://www.w3.org/ns/did/v1',
            'id' => $did,
            'verificationMethod' => [
                [
                    'id' => $did . '#key-1',
                    'type' => 'JsonWebKey2020',
                    'controller' => $did,
                    'publicKeyJwk' => $this->p256Jwk,
                ],
            ],
        ];
    }

    // ─── Network selection ──────────────────────────────────────────────

    public function testTrustNetworksDefaultsCoverEbsiAndBlue(): void
    {
        $networks = new TrustNetworks();

        $ebsi = $networks->forDid('did:ebsi:zabc');
        $this->assertSame('EBSI', $ebsi['name']);
        $this->assertStringContainsString('api-pilot.ebsi.eu', $ebsi['config']['did_registry_url']);
        $this->assertStringContainsString('api-pilot.ebsi.rediris.es', $ebsi['config']['fallback_did_registry_url']);
        $this->assertCount(1, $ebsi['alternate_configs']);

        $blue = $networks->forDid('did:blue:zabc');
        $this->assertSame('BLUE', $blue['name']);
        $this->assertStringContainsString('api.blue.rediris.es', $blue['config']['did_registry_url']);
        $this->assertCount(2, $blue['alternate_configs']);
        $this->assertSame('PRE', $blue['alternate_configs'][0]['label']);
        $this->assertSame('DES', $blue['alternate_configs'][1]['label']);

        $this->assertNull($networks->forDid('did:key:zabc'));
    }

    public function testTrustNetworksUserOverrideReplacesEntry(): void
    {
        $networks = new TrustNetworks([
            'did:blue' => [
                'name' => 'BLUE',
                'config' => ['did_registry_url' => 'https://custom.example.org/did-registry/v5'],
            ],
        ]);

        $blue = $networks->forDid('did:blue:zabc');
        $this->assertSame('https://custom.example.org/did-registry/v5', $blue['config']['did_registry_url']);
        $this->assertArrayNotHasKey('alternate_configs', $blue);
    }

    // ─── DID resolution ─────────────────────────────────────────────────

    public function testResolveDidBlueFromPrimaryRegistry(): void
    {
        $did = 'did:blue:ztest123';
        $requests = [];
        $client = $this->mockClient([
            new Response(200, [], json_encode($this->didDocumentFor($did))),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $key = $resolver->resolvePublicKey($did . '#key-1');

        $this->assertInstanceOf(Key::class, $key);
        $this->assertStringContainsString('api.blue.rediris.es/did-registry/v5/identifiers/', $requests[0]);
    }

    public function testResolveDidBlueFallsBackToPreAndDesOn404(): void
    {
        $did = 'did:blue:ztest123';
        $requests = [];
        $client = $this->mockClient([
            new Response(404),
            new Response(404),
            new Response(200, [], json_encode($this->didDocumentFor($did))),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $key = $resolver->resolvePublicKey($did);

        $this->assertInstanceOf(Key::class, $key);
        $this->assertCount(3, $requests);
        $this->assertStringContainsString('api.blue.rediris.es', $requests[0]);
        $this->assertStringContainsString('api-pre.blue.rediris.es', $requests[1]);
        $this->assertStringContainsString('api-des.blue.rediris.es', $requests[2]);
    }

    public function testResolveDidEbsiUsesRedirisMirrorOnNetworkError(): void
    {
        $did = 'did:ebsi:ztest456';
        $requests = [];
        $client = $this->mockClient([
            new ConnectException('Connection refused', new Request('GET', 'test')),
            new Response(200, [], json_encode($this->didDocumentFor($did))),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $key = $resolver->resolvePublicKey($did);

        $this->assertInstanceOf(Key::class, $key);
        $this->assertStringContainsString('api-pilot.ebsi.eu', $requests[0]);
        $this->assertStringContainsString('api-pilot.ebsi.rediris.es', $requests[1]);
    }

    public function testResolveDidNotFoundInAnyRegistryThrows(): void
    {
        $client = $this->mockClient([
            new Response(404),
            new Response(404),
            new Response(404),
        ]);

        $resolver = new TrustChainResolver([], null, $client, [], false);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('[BLUE] DID not found');

        $resolver->resolvePublicKey('did:blue:zmissing');
    }

    public function testResolveDidJwkLocally(): void
    {
        $jcs = json_encode($this->p256Jwk);
        $did = 'did:jwk:' . $this->b64u($jcs);

        // No HTTP responses queued — resolution must be local
        $resolver = new TrustChainResolver([], null, $this->mockClient([]), [], false);
        $key = $resolver->resolvePublicKey($did);

        $this->assertInstanceOf(Key::class, $key);
    }

    public function testResolveDidWebFetchesWellKnown(): void
    {
        $did = 'did:web:idp.example.org';
        $requests = [];
        $client = $this->mockClient([
            new Response(200, [], json_encode($this->didDocumentFor($did))),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $key = $resolver->resolvePublicKey($did);

        $this->assertInstanceOf(Key::class, $key);
        $this->assertSame('https://idp.example.org/.well-known/did.json', $requests[0]);
    }

    public function testResolveDidWebIdMismatchThrows(): void
    {
        $client = $this->mockClient([
            new Response(200, [], json_encode($this->didDocumentFor('did:web:evil.example.org'))),
        ]);

        $resolver = new TrustChainResolver([], null, $client, [], false);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('DID document ID mismatch');

        $resolver->resolvePublicKey('did:web:idp.example.org');
    }

    // ─── Issuer trust ───────────────────────────────────────────────────

    public function testStaticTrustedIssuerAccepted(): void
    {
        $resolver = new TrustChainResolver(['did:blue:zissuer'], null, $this->mockClient([]), [], false);

        $resolver->verifyIssuerTrust('did:blue:zissuer');
        $this->addToAssertionCount(1);
    }

    public function testBlueIssuerTrustedViaTir(): void
    {
        $issuer = 'did:blue:zissuer';
        $requests = [];
        $client = $this->mockClient([
            new Response(200, [], json_encode(['did' => $issuer, 'attributes' => []])),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $resolver->verifyIssuerTrust($issuer);

        $this->assertStringContainsString(
            'api.blue.rediris.es/trusted-issuers-registry/v5/issuers/',
            $requests[0]
        );
    }

    public function testBlueIssuerTrustedViaPreTirAfter404(): void
    {
        $issuer = 'did:blue:zissuer';
        $requests = [];
        $client = $this->mockClient([
            new Response(404),
            new Response(200, [], json_encode(['did' => $issuer, 'attributes' => []])),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $resolver->verifyIssuerTrust($issuer);

        $this->assertStringContainsString('api-pre.blue.rediris.es', $requests[1]);
    }

    public function testBlueIssuerNotInAnyTirThrows(): void
    {
        $client = $this->mockClient([
            new Response(404),
            new Response(404),
            new Response(404),
        ]);

        $resolver = new TrustChainResolver([], null, $client, [], false);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('not registered in the BLUE Trusted Issuers Registry');

        $resolver->verifyIssuerTrust('did:blue:zuntrusted');
    }

    public function testEbsiIssuerTrustedViaMirrorOnNetworkError(): void
    {
        $issuer = 'did:ebsi:zissuer';
        $requests = [];
        $client = $this->mockClient([
            new ConnectException('Connection refused', new Request('GET', 'test')),
            new Response(200, [], json_encode(['did' => $issuer, 'attributes' => []])),
        ], $requests);

        $resolver = new TrustChainResolver([], null, $client, [], false);
        $resolver->verifyIssuerTrust($issuer);

        $this->assertStringContainsString('api-pilot.ebsi.rediris.es', $requests[1]);
    }

    public function testDevModeAcceptsNonNetworkIssuerWithoutTrustSources(): void
    {
        // did:key has no trust network; with no static list and no legacy
        // registry the resolver accepts it (dev mode, logged warning)
        $resolver = new TrustChainResolver([], null, $this->mockClient([]), [], false);

        $resolver->verifyIssuerTrust('did:key:zsomeissuer');
        $this->addToAssertionCount(1);
    }

    public function testNonNetworkIssuerRejectedWhenStaticListConfigured(): void
    {
        $resolver = new TrustChainResolver(['did:key:zother'], null, $this->mockClient([]), [], false);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('not trusted');

        $resolver->verifyIssuerTrust('did:key:zsomeissuer');
    }
}
