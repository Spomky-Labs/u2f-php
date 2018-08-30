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

namespace U2FAuthentication\Tests\Unit\Fido\AttestationStatement;

use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatement;
use U2FAuthentication\Fido2\AttestationStatement\NoneAttestationStatementSupport;
use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\CollectedClientData;

/**
 * @group Unit
 * @group Fido2
 */
class NoneAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     */
    public function theAttestationStatementIsNotValid()
    {
        $support = new NoneAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([]);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $collectedClientData = $this->prophesize(CollectedClientData::class);

        static::assertEquals('none', $support->name());
        static::assertTrue($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }

    /**
     * @test
     */
    public function theAttestationStatementIsValid()
    {
        $support = new NoneAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([
            'x5c' => ['FOO'],
        ]);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $collectedClientData = $this->prophesize(CollectedClientData::class);

        static::assertEquals('none', $support->name());
        static::assertFalse($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }
}
