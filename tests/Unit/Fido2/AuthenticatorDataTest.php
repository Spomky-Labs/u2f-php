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

use CBOR\CBORObject;
use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestedCredentialData;
use U2FAuthentication\Fido2\AuthenticatorData;

/**
 * @group Unit
 * @group Fido2
 */
class AuthenticatorDataTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorDataCanBeCreatedAndValueAccessed()
    {
        $attestedCredentialData = $this->prophesize(AttestedCredentialData::class);
        $extensions = $this->prophesize(CBORObject::class);

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
        static::assertInstanceOf(CBORObject::class, $authenticatorData->getExtensions());
    }
}
