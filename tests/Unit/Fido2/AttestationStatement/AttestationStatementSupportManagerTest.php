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
use Prophecy\Argument;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatement;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;
use U2FAuthentication\Fido2\AuthenticatorData;

/**
 * @group Unit
 * @group Fido2
 */
class AttestationStatementSupportManagerTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation format "bar" is not supported.
     */
    public function theAttestationFormatIsNotSupported()
    {
        $attestationStatementSupport = $this->prophesize(AttestationStatementSupport::class);
        $attestationStatementSupport->name()->willReturn('FOO');

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getFmt()->willReturn('bar');
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        $manager = new AttestationStatementSupportManager();
        $manager->add($attestationStatementSupport->reveal());

        $manager->isValid(
            'FOO',
            $attestationStatement->reveal(),
            $authenticatorData->reveal()
        );
    }

    /**
     * @test
     */
    public function theAttestationFormatIsNotValid()
    {
        $attestationStatementSupport = $this->prophesize(AttestationStatementSupport::class);
        $attestationStatementSupport->name()->willReturn('FOO');
        $attestationStatementSupport->isValid(Argument::type('string'), Argument::type(AttestationStatement::class), Argument::type(AuthenticatorData::class))->willReturn(false);

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getFmt()->willReturn('FOO');
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        $manager = new AttestationStatementSupportManager();
        $manager->add($attestationStatementSupport->reveal());

        static::assertFalse($manager->isValid(
            'foo',
            $attestationStatement->reveal(),
            $authenticatorData->reveal()
        ));
    }

    /**
     * @test
     */
    public function theAttestationFormatIsValid()
    {
        $attestationStatementSupport = $this->prophesize(AttestationStatementSupport::class);
        $attestationStatementSupport->name()->willReturn('FOO');
        $attestationStatementSupport->isValid(Argument::type('string'), Argument::type(AttestationStatement::class), Argument::type(AuthenticatorData::class))->willReturn(true);

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getFmt()->willReturn('FOO');
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        $manager = new AttestationStatementSupportManager();
        $manager->add($attestationStatementSupport->reveal());

        static::assertTrue($manager->isValid(
            'foo',
            $attestationStatement->reveal(),
            $authenticatorData->reveal()
        ));
    }
}
