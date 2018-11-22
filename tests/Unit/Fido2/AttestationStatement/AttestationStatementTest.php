<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace U2FAuthentication\Tests\Unit\Fido2\AttestationStatement;

use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatement;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \U2FAuthentication\Fido2\AttestationStatement\AttestationStatement
 */
class AttestationStatementTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement has no key "foo".
     */
    public function anAttestationStatementCanBeCreated()
    {
        $statement = new AttestationStatement(
            'fmt',
            [
                'bar' => 'FOO',
            ]
        );

        static::assertEquals('fmt', $statement->getFmt());
        static::assertEquals(['bar' => 'FOO'], $statement->getAttStmt());
        static::assertTrue($statement->has('bar'));
        static::assertFalse($statement->has('foo'));
        static::assertEquals('FOO', $statement->get('bar'));
        $statement->get('foo');
    }
}
