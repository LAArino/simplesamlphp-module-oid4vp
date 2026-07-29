<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oid4vp\Mapping;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oid4vp\Mapping\CredentialMapper;

class CredentialMapperTest extends TestCase
{
    private function sampleCredentialSubject(): array
    {
        return [
            'id' => 'did:ebsi:z123456789',
            'eduPersonPrincipalName' => 'jdoe@example.org',
            'schacHomeOrganization' => 'example.org',
            'eduPersonScopedAffiliation' => 'student@example.org',
            'eduPersonPrimaryAffiliation' => 'student',
            'eduPersonAssurance' => 'https://refeds.org/assurance/IAP/low',
            'displayName' => 'John Doe',
            'commonName' => 'John Doe',
            'familyName' => 'Doe',
            'firstName' => 'John',
            'mail' => 'jdoe@example.org',
            'schacPersonalUniqueCode' => 'urn:schac:personalUniqueCode:int:esi:abc123',
            'identifier' => 'jdoe',
        ];
    }

    public function testMapFriendlyNames(): void
    {
        $mapper = new CredentialMapper(false);
        $result = $mapper->map($this->sampleCredentialSubject());

        $this->assertSame(['jdoe@example.org'], $result['eduPersonPrincipalName']);
        $this->assertSame(['example.org'], $result['schacHomeOrganization']);
        $this->assertSame(['student@example.org'], $result['eduPersonScopedAffiliation']);
        $this->assertSame(['student'], $result['eduPersonAffiliation']);
        $this->assertSame(['John Doe'], $result['displayName']);
        $this->assertSame(['John Doe'], $result['cn']);
        $this->assertSame(['Doe'], $result['sn']);
        $this->assertSame(['John'], $result['givenName']);
        $this->assertSame(['jdoe@example.org'], $result['mail']);
        $this->assertSame(['jdoe'], $result['uid']);
    }

    public function testMapOidFormat(): void
    {
        $mapper = new CredentialMapper(true);
        $result = $mapper->map($this->sampleCredentialSubject());

        $this->assertArrayHasKey('urn:oid:1.3.6.1.4.1.5923.1.1.1.6', $result);
        $this->assertSame(['jdoe@example.org'], $result['urn:oid:1.3.6.1.4.1.5923.1.1.1.6']);
        $this->assertArrayHasKey('urn:oid:1.3.6.1.4.1.25178.1.2.9', $result);
        $this->assertArrayHasKey('urn:oid:0.9.2342.19200300.100.1.3', $result);
    }

    public function testMapGeneratesTargetedId(): void
    {
        $mapper = new CredentialMapper(false);
        $result = $mapper->map($this->sampleCredentialSubject());

        $this->assertArrayHasKey('eduPersonTargetedID', $result);
        $this->assertSame([md5('did:ebsi:z123456789')], $result['eduPersonTargetedID']);
    }

    public function testMapOidTargetedId(): void
    {
        $mapper = new CredentialMapper(true);
        $result = $mapper->map($this->sampleCredentialSubject());

        $this->assertArrayHasKey('urn:oid:1.3.6.1.4.1.5923.1.1.1.10', $result);
    }

    public function testMapHandlesArrayValues(): void
    {
        $mapper = new CredentialMapper(false);
        $subject = [
            'eduPersonScopedAffiliation' => ['student@example.org', 'member@example.org'],
            'displayName' => 'Test User',
        ];

        $result = $mapper->map($subject);

        $this->assertSame(
            ['student@example.org', 'member@example.org'],
            $result['eduPersonScopedAffiliation']
        );
    }

    public function testMapSkipsMissingFields(): void
    {
        $mapper = new CredentialMapper(false);
        $result = $mapper->map(['displayName' => 'Minimal User']);

        $this->assertSame(['Minimal User'], $result['displayName']);
        $this->assertArrayNotHasKey('mail', $result);
        $this->assertArrayNotHasKey('uid', $result);
        $this->assertArrayNotHasKey('eduPersonTargetedID', $result);
    }

    public function testMapEmptySubject(): void
    {
        $mapper = new CredentialMapper(false);
        $this->assertEmpty($mapper->map([]));
    }

    public function testMapWithCustomOverrides(): void
    {
        $mapper = new CredentialMapper(false, ['mail' => 'customMailAttr']);
        $result = $mapper->map(['mail' => 'test@example.org']);

        $this->assertArrayHasKey('customMailAttr', $result);
        $this->assertSame(['test@example.org'], $result['customMailAttr']);
    }

    public function testValidateRequiredAllPresent(): void
    {
        $mapper = new CredentialMapper();
        $this->assertEmpty($mapper->validateRequired($this->sampleCredentialSubject()));
    }

    public function testValidateRequiredMissingFields(): void
    {
        $mapper = new CredentialMapper();
        $missing = $mapper->validateRequired(['mail' => 'test@example.org']);

        $this->assertContains('id', $missing);
        $this->assertContains('identifier', $missing);
        $this->assertContains('eduPersonScopedAffiliation', $missing);
    }

    public function testValidateRequiredEmptyValues(): void
    {
        $mapper = new CredentialMapper();
        $missing = $mapper->validateRequired([
            'id' => '',
            'identifier' => 'jdoe',
            'eduPersonScopedAffiliation' => 'student@example.org',
        ]);

        $this->assertSame(['id'], $missing);
    }

    /**
     * The default required set must match the EducationalID schema, which marks
     * everything except id, identifier and eduPersonScopedAffiliation as optional.
     * Being stricter rejects credentials that are perfectly valid — this was hit
     * with a real wallet against the BLUE network.
     */
    public function testValidateRequiredAcceptsSchemaMinimalCredential(): void
    {
        $mapper = new CredentialMapper();

        $missing = $mapper->validateRequired([
            'id' => 'did:key:z123',
            'identifier' => 'jdoe',
            'eduPersonScopedAffiliation' => ['student@example.org'],
        ]);

        $this->assertEmpty($missing);
    }

    public function testValidateRequiredTreatsEmptyArrayAsMissing(): void
    {
        $mapper = new CredentialMapper();

        $missing = $mapper->validateRequired([
            'id' => 'did:key:z123',
            'identifier' => 'jdoe',
            'eduPersonScopedAffiliation' => [],
        ]);

        $this->assertSame(['eduPersonScopedAffiliation'], $missing);
    }

    public function testValidateRequiredHonoursConfiguredList(): void
    {
        $mapper = new CredentialMapper(false, [], ['mail', 'displayName']);

        $this->assertSame(
            ['displayName'],
            $mapper->validateRequired(['mail' => 'test@example.org'])
        );

        // The schema defaults no longer apply when a list is configured
        $this->assertEmpty($mapper->validateRequired([
            'mail' => 'test@example.org',
            'displayName' => 'Test',
        ]));
    }
}
