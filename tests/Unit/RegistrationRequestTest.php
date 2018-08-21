<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace U2FAuthentication\Tests\Unit;

use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido\KeyHandler;
use U2FAuthentication\Fido\PublicKey;
use U2FAuthentication\Fido\RegisteredKey;
use U2FAuthentication\Fido\RegistrationRequest;

/**
 * @group Unit
 */
final class RegistrationRequestTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid registered keys list.
     */
    public function theRegistrationRequestDoesNotContainValidRegisteredKeys()
    {
        RegistrationRequest::create('https://twofactors:4043', ['bad value']);
    }

    /**
     * @test
     */
    public function iCanCreateARegistrationRequestAndUseIt()
    {
        $registered_key = RegisteredKey::create(
            'U2F_V2',
            KeyHandler::create('foo'),
            PublicKey::create('bar'),
            'bar'
        );
        $request = RegistrationRequest::create(
            'https://twofactors:4043',
            [$registered_key]
        );

        static::assertEquals('https://twofactors:4043', $request->getApplicationId());
        static::assertEquals(32, mb_strlen($request->getChallenge(), '8bit'));
        static::assertArrayHasKey('registerRequests', $request->jsonSerialize());
        static::assertArrayHasKey('registeredKeys', $request->jsonSerialize());
        static::assertArrayHasKey('appId', $request->jsonSerialize());
        static::assertInternalType('array', $request->jsonSerialize()['registerRequests']);
        static::assertEquals(1, \count($request->jsonSerialize()['registerRequests']));
        static::assertInternalType('array', $request->jsonSerialize()['registeredKeys']);
        static::assertEquals(1, \count($request->jsonSerialize()['registeredKeys']));
        static::assertEquals([Base64Url::encode('foo') => $registered_key], $request->getRegisteredKeys());
    }
}
