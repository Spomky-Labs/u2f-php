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

use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatement;
use U2FAuthentication\Fido2\AttestationStatement\FidoU2FAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestedCredentialData;
use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\CollectedClientData;

/**
 * @group Unit
 * @group Fido2
 */
class FidoU2FAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "sig" is missing.
     */
    public function theAttestationStatementDoesNotContainTheRequiredSignature()
    {
        $support = new FidoU2FAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn();
        $attestationStatement->has('sig')->willReturn(false);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $collectedClientData = $this->prophesize(CollectedClientData::class);

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "x5c" is missing.
     */
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList()
    {
        $support = new FidoU2FAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn();
        $attestationStatement->has('sig')->willReturn(true);
        $attestationStatement->has('x5c')->willReturn(false);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $collectedClientData = $this->prophesize(CollectedClientData::class);

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "x5c" must be a list with at least one certificate.
     */
    public function theAttestationStatementDoesNotContainAValidCertificateList()
    {
        $support = new FidoU2FAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([
            'sig' => 'FOO',
            'x5c' => ['FOO'],
        ]);
        $attestationStatement->has('sig')->willReturn(true);
        $attestationStatement->has('x5c')->willReturn(true);
        $attestationStatement->get('x5c')->willReturn('FOO');
        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $collectedClientData = $this->prophesize(CollectedClientData::class);

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "x5c" must be a list with at least one certificate.
     */
    public function theAttestationStatementContainsAnEmptyCertificateList()
    {
        $support = new FidoU2FAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([
            'sig' => 'FOO',
            'x5c' => ['FOO'],
        ]);
        $attestationStatement->has('sig')->willReturn(true);
        $attestationStatement->has('x5c')->willReturn(true);
        $attestationStatement->get('x5c')->willReturn([]);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $collectedClientData = $this->prophesize(CollectedClientData::class);

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }

    /**
     * @test
     */
    public function theAttestationStatementContain()
    {
        $support = new FidoU2FAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([
            'sig' => 'FOO',
            'x5c' => [
                Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ'),
            ],
        ]);
        $attestationStatement->has('sig')->willReturn(true);
        $attestationStatement->has('x5c')->willReturn(true);
        $attestationStatement->get('x5c')->willReturn([Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ')]);

        $attestedCredentialData = $this->prophesize(AttestedCredentialData::class);
        $attestedCredentialData->getCredentialId()->willReturn('CREDENTIAL_ID');
        $attestedCredentialData->getCredentialPublicKey()->willReturn();

        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $authenticatorData->getRpIdHash()->willReturn('FOO');
        $authenticatorData->getAttestedCredentialData()->willReturn($attestedCredentialData->reveal());

        $collectedClientData = $this->prophesize(CollectedClientData::class);
        $collectedClientData->getRawData()->willReturn('FOO');

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->isValid($attestationStatement->reveal(), $authenticatorData->reveal(), $collectedClientData->reveal()));
    }
}
