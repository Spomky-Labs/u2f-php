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
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtension;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;
use U2FAuthentication\Fido2\PublicKeyCredentialRequestOptions;

/**
 * @group Unit
 * @group Fido2
 *
 * @covers \U2FAuthentication\Fido2\PublicKeyCredentialRequestOptions
 */
class PublicKeyCredentialRequestOptionsTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialRequestOptionsCanBeCreatedAndValueAccessed()
    {
        $extensions = new AuthenticationExtensionsClientInputs();
        $extensions->add(new AuthenticationExtension('foo', 'bar'));

        $credential = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);

        $publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions('challenge', 1000, 'rp_id', [$credential], 'user_verification', $extensions);

        static::assertEquals('challenge', $publicKeyCredentialRequestOptions->getChallenge());
        static::assertEquals(1000, $publicKeyCredentialRequestOptions->getTimeout());
        static::assertEquals('rp_id', $publicKeyCredentialRequestOptions->getRpId());
        static::assertEquals([$credential], $publicKeyCredentialRequestOptions->getAllowCredentials());
        static::assertEquals('user_verification', $publicKeyCredentialRequestOptions->getUserVerification());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $publicKeyCredentialRequestOptions->getExtensions());
        static::assertEquals('{"challenge":"Y2hhbGxlbmdl","rpId":"rp_id","userVerification":"user_verification","allowCredentials":[{"type":"type","id":"aWQ=","transports":["transport"]}],"extensions":{"foo":"bar"},"timeout":1000}', \Safe\json_encode($publicKeyCredentialRequestOptions));
    }
}
