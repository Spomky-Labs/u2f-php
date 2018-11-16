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
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;
use U2FAuthentication\Fido2\PublicKeyCredentialCreationOptions;
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

/**
 * @group Unit
 * @group Fido2
 */
class PublicKeyCredentialCreationOptionsTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialCreationOptionsCanBeCreatedAndValueAccessed()
    {
        $rp = $this->prophesize(PublicKeyCredentialRpEntity::class);
        $rp->jsonSerialize()->willReturn(['RP']);
        $user = $this->prophesize(PublicKeyCredentialUserEntity::class);
        $user->jsonSerialize()->willReturn(['USER']);

        $credential = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);
        $credentialParameters = new PublicKeyCredentialParameters('type', -100);

        $options = new PublicKeyCredentialCreationOptions(
            $rp->reveal(),
            $user->reveal(),
            'challenge',
            [$credentialParameters],
            1000,
            [$credential],
            new AuthenticatorSelectionCriteria(),
            'attestation',
            new AuthenticationExtensionsClientInputs()
        );

        static::assertEquals('challenge', $options->getChallenge());
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
        static::assertEquals([$credential], $options->getExcludeCredentials());
        static::assertEquals([$credentialParameters], $options->getPubKeyCredParams());
        static::assertEquals('attestation', $options->getAttestation());
        static::assertEquals(1000, $options->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $options->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $options->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $options->getAuthenticatorSelection());
        static::assertEquals('{"rp":["RP"],"pubKeyCredParams":[{"type":"type","alg":-100}],"challenge":"Y2hhbGxlbmdl","attestation":"attestation","user":["USER"],"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"excludeCredentials":[{"type":"type","id":"aWQ=","transports":["transport"]}],"timeout":1000}', \Safe\json_encode($options));
    }
}
