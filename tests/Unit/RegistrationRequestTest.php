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

use PHPUnit\Framework\TestCase;
use U2FAuthentication\RegistrationRequest;

/**
 * @group Unit
 */
final class RegistrationRequestTest extends TestCase
{
    /**
     * @test
     */
    public function iCanCreateARegistrationRequestAndUseIt()
    {
        $request = RegistrationRequest::create('https://twofactors:4043');

        self::assertEquals('https://twofactors:4043', $request->getApplicationId());
        self::assertEquals(32, mb_strlen($request->getChallenge(), '8bit'));
        self::assertArrayHasKey('version', $request->jsonSerialize());
        self::assertArrayHasKey('challenge', $request->jsonSerialize());
        self::assertArrayHasKey('appId', $request->jsonSerialize());
    }
}
