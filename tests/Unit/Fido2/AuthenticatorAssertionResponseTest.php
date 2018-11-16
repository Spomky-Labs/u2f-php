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
use U2FAuthentication\Fido2\AuthenticatorAssertionResponse;
use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\CollectedClientData;

/**
 * @group Unit
 * @group Fido2
 */
class AuthenticatorAssertionResponseTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorAssertionResponseCanBeCreatedAndValueAccessed()
    {
        $clientDataJSON = $this->prophesize(CollectedClientData::class);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        $authenticatorAssertionResponse = new AuthenticatorAssertionResponse(
            $clientDataJSON->reveal(),
            $authenticatorData->reveal(),
            'signature',
            'user_handle'
        );

        static::assertInstanceOf(CollectedClientData::class, $authenticatorAssertionResponse->getClientDataJSON());
        static::assertInstanceOf(AuthenticatorData::class, $authenticatorAssertionResponse->getAuthenticatorData());
        static::assertEquals('signature', $authenticatorAssertionResponse->getSignature());
        static::assertEquals('user_handle', $authenticatorAssertionResponse->getUserHandle());
    }
}
