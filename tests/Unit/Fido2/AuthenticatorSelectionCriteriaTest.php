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
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \U2FAuthentication\Fido2\AuthenticatorSelectionCriteria
 */
class AuthenticatorSelectionCriteriaTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorSelectionCriteriaCanBeCreatedAndValueAccessed()
    {
        $authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria('authenticator_attachment', true, 'user_verification');

        static::assertEquals('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertEquals('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertEquals('{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}', \Safe\json_encode($authenticatorSelectionCriteria));
    }
}
