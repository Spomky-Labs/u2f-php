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

namespace U2FAuthentication\Tests\Unit\Fido2;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\TrueObject;
use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestedCredentialData;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use U2FAuthentication\Fido2\AuthenticatorData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \U2FAuthentication\Fido2\AttestedCredentialData
 */
class AuthenticatorDataTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorDataCanBeCreatedAndValueAccessed()
    {
        $attestedCredentialData = $this->prophesize(AttestedCredentialData::class);
        $extensions = $this->prophesize(AuthenticationExtensionsClientOutputs::class);

        $authenticatorData = new AuthenticatorData('auth_data', 'rp_id_hash', 'A', 100, $attestedCredentialData->reveal(), $extensions->reveal());

        static::assertEquals('auth_data', $authenticatorData->getAuthData());
        static::assertEquals('rp_id_hash', $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertEquals(100, $authenticatorData->getSignCount());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse1());
        static::assertEquals(0, $authenticatorData->getReservedForFutureUse2());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
        static::assertInstanceOf(AuthenticationExtensionsClientOutputs::class, $authenticatorData->getExtensions());
    }

    private function buildExtensions(): MapObject
    {
        $map = new MapObject([
            new MapItem(new ByteStringObject('loc'), new TrueObject()),
        ]);

        return $map;
    }
}
