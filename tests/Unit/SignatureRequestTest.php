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
use U2FAuthentication\SignatureRequest;

/**
 * @group Unit
 */
final class SignatureRequestTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid registered keys list.
     */
    public function theSignatureRequestDoesNotContainValidRegisteredKeys()
    {
        SignatureRequest::create('https://twofactors:4043', ['foo']);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported key handle.
     */
    public function theSignatureRequestDoesNotContainTheRegisteredKey()
    {
        $request = SignatureRequest::create('https://twofactors:4043', []);
        $request->getRegisteredKey(KeyHandle::create('foo'));
    }

    /**
     * @test
     */
    public function iCanCreateASignatureRequestAndUseIt()
    {
        $key_handle = KeyHandle::create(Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ'));
        $registered_key = RegisteredKey::create(
            'U2F_V2',
            $key_handle,
            PublicKey::create(Base64Url::decode('BFeWllSolex8diHswKHW6z7KmtrMypMnKNZehwDSP9RPn3GbMeB_WaRP0Ovzaca1g9ff3o-tRDHj_niFpNmjyDo')),
            '-----BEGIN PUBLIC KEY-----'.PHP_EOL.
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV5aWVKiV7Hx2IezAodbrPsqa2szK'.PHP_EOL.
            'kyco1l6HANI/1E+fcZsx4H9ZpE/Q6/NpxrWD19/ej61EMeP+eIWk2aPIOg=='.PHP_EOL.
            '-----END PUBLIC KEY-----'.PHP_EOL
        );
        $request = SignatureRequest::create('https://twofactors:4043', [$registered_key]);
        $request->addRegisteredKey(
            $registered_key
        );

        self::assertEquals('https://twofactors:4043', $request->getApplicationId());
        self::assertEquals(32, mb_strlen($request->getChallenge(), '8bit'));
        self::assertTrue($request->hasRegisteredKey($key_handle));
        self::assertSame($registered_key, $request->getRegisteredKey($key_handle));
        self::assertEquals([Base64Url::encode($registered_key->getKeyHandler()) => $registered_key], $request->getRegisteredKeys());
        self::assertArrayHasKey('registeredKeys', $request->jsonSerialize());
        self::assertArrayHasKey('challenge', $request->jsonSerialize());
        self::assertArrayHasKey('appId', $request->jsonSerialize());
    }
}
