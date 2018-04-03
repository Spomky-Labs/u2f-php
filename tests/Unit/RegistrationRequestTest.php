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
use U2FAuthentication\KeyHandle;
use U2FAuthentication\PublicKey;
use U2FAuthentication\RegisteredKey;
use U2FAuthentication\RegistrationRequest;

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
            KeyHandle::create('foo'),
            PublicKey::create('bar'),
            'bar'
        );
        $request = RegistrationRequest::create(
            'https://twofactors:4043',
            [$registered_key]
        );

        self::assertEquals('https://twofactors:4043', $request->getApplicationId());
        self::assertEquals(32, mb_strlen($request->getChallenge(), '8bit'));
        self::assertArrayHasKey('registerRequests', $request->jsonSerialize());
        self::assertArrayHasKey('registeredKeys', $request->jsonSerialize());
        self::assertArrayHasKey('appId', $request->jsonSerialize());
        self::assertInternalType('array', $request->jsonSerialize()['registerRequests']);
        self::assertEquals(1, count($request->jsonSerialize()['registerRequests']));
        self::assertInternalType('array', $request->jsonSerialize()['registeredKeys']);
        self::assertEquals(1, count($request->jsonSerialize()['registeredKeys']));
        self::assertEquals([Base64Url::encode('foo') => $registered_key], $request->getRegisteredKeys());
    }
}
