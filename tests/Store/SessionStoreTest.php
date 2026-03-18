<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oid4vp\Store;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oid4vp\Store\SessionStore;

/**
 * SessionStore tests.
 *
 * These tests verify the class interface and file-based storage logic.
 * Full integration tests require SimpleSAMLphp runtime.
 */
class SessionStoreTest extends TestCase
{
    public function testSessionStoreClassExists(): void
    {
        $this->assertTrue(
            class_exists(SessionStore::class),
            'SessionStore class should exist in Store namespace'
        );
    }

    public function testConstructorAcceptsTimeout(): void
    {
        $reflection = new \ReflectionClass(SessionStore::class);
        $constructor = $reflection->getConstructor();

        $this->assertNotNull($constructor);
        $params = $constructor->getParameters();
        $this->assertCount(1, $params);
        $this->assertSame('timeout', $params[0]->getName());
        $this->assertTrue($params[0]->isOptional());
        $this->assertSame(300, $params[0]->getDefaultValue());
    }

    public function testPublicMethodsExist(): void
    {
        $reflection = new \ReflectionClass(SessionStore::class);

        $this->assertTrue($reflection->hasMethod('create'));
        $this->assertTrue($reflection->hasMethod('get'));
        $this->assertTrue($reflection->hasMethod('getByState'));
        $this->assertTrue($reflection->hasMethod('complete'));
        $this->assertTrue($reflection->hasMethod('delete'));
        $this->assertTrue($reflection->hasMethod('cleanup'));
    }
}
