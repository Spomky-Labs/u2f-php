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

use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestationStatement\AttestationObject;
use U2FAuthentication\Fido2\AuthenticatorAttestationResponse;
use U2FAuthentication\Fido2\CollectedClientData;

/**
 * @group Unit
 * @group Fido2
 */
class AuthenticatorAttestationResponseTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorAttestationResponseCanBeCreatedAndValueAccessed()
    {
        $clientDataJSON = $this->prophesize(CollectedClientData::class);
        $attestationObject = $this->prophesize(AttestationObject::class);

        $authenticatorAttestationResponse = new AuthenticatorAttestationResponse(
            $clientDataJSON->reveal(),
            $attestationObject->reveal()
        );

        static::assertInstanceOf(CollectedClientData::class, $authenticatorAttestationResponse->getClientDataJSON());
        static::assertInstanceOf(AttestationObject::class, $authenticatorAttestationResponse->getAttestationObject());
    }
}
