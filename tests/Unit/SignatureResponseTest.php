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
use Prophecy\Argument;
use U2FAuthentication\KeyHandle;
use U2FAuthentication\PublicKey;
use U2FAuthentication\RegisteredKey;
use U2FAuthentication\SignatureRequest;
use U2FAuthentication\SignatureResponse;

/**
 * @group Unit
 */
final class SignatureResponseTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid response.
     */
    public function theSignatureRequestContainsAnError()
    {
        SignatureResponse::create([
            'errorCode' => 1,
        ]);
    }

    /**
     * @test
     */
    public function iCanCreateASignatureResponseAndUseIt()
    {
        $response = SignatureResponse::create(
            $this->getValidSignatureResponse()
        );

        self::assertEquals('{"typ":"navigator.id.getAssertion","challenge":"F-zksRh5thzKyZR6O0Fr7QxlZ-xEX9_mNH8H3cHn_Po","origin":"https://twofactors:4043","cid_pubkey":"unused"}', $response->getClientData()->getRawData());
        self::assertEquals(Base64Url::decode('MEUCIFPqMs0jYrX31BmYEUhIo2wcrW8_GcMWb5yklQvdKAJvAiEA6DFuWbcFKKKbTQeTPtlv40o09MjTpFp1P8NXvWo-7zA'), $response->getSignature());
        self::assertEquals('navigator.id.getAssertion', $response->getClientData()->getType());
        self::assertEquals('https://twofactors:4043', $response->getClientData()->getOrigin());
        self::assertEquals(Base64Url::decode('F-zksRh5thzKyZR6O0Fr7QxlZ-xEX9_mNH8H3cHn_Po'), $response->getClientData()->getChallenge());
        self::assertEquals('unused', $response->getClientData()->getChannelIdPublicKey());

        self::assertEquals(Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ'), $response->getKeyHandle()->getValue());
        self::assertEquals(186, $response->getCounter());
        self::assertTrue($response->isUserPresence());

        $request = $this->prophesize(SignatureRequest::class);
        $request->getChallenge()->willReturn(Base64Url::decode('F-zksRh5thzKyZR6O0Fr7QxlZ-xEX9_mNH8H3cHn_Po'));
        $request->getApplicationId()->willReturn('https://twofactors:4043');
        $request->hasRegisteredKey(Argument::type(KeyHandle::class))->willReturn(true);
        $request->getRegisteredKey(Argument::type(KeyHandle::class))->willReturn(
            RegisteredKey::create(
                'U2F_V2',
                KeyHandle::create(Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ')),
                PublicKey::create(Base64Url::decode('BFeWllSolex8diHswKHW6z7KmtrMypMnKNZehwDSP9RPn3GbMeB_WaRP0Ovzaca1g9ff3o-tRDHj_niFpNmjyDo')),
                '-----BEGIN PUBLIC KEY-----'.PHP_EOL.
                'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV5aWVKiV7Hx2IezAodbrPsqa2szK'.PHP_EOL.
                'kyco1l6HANI/1E+fcZsx4H9ZpE/Q6/NpxrWD19/ej61EMeP+eIWk2aPIOg=='.PHP_EOL.
                '-----END PUBLIC KEY-----'.PHP_EOL
            )
        );

        self::assertTrue($response->isValid($request->reveal(), 180));
    }

    /**
     * @return array
     */
    private function getValidSignatureResponse(): array
    {
        return [
            'keyHandle'     => 'Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ',
            'clientData'    => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiRi16a3NSaDV0aHpLeVpSNk8wRnI3UXhsWi14RVg5X21OSDhIM2NIbl9QbyIsIm9yaWdpbiI6Imh0dHBzOi8vdHdvZmFjdG9yczo0MDQzIiwiY2lkX3B1YmtleSI6InVudXNlZCJ9',
            'signatureData' => 'AQAAALowRQIgU-oyzSNitffUGZgRSEijbBytbz8ZwxZvnKSVC90oAm8CIQDoMW5ZtwUooptNB5M-2W_jSjT0yNOkWnU_w1e9aj7vMA',
        ];
    }
}
