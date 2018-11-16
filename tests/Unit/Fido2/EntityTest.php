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
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

/**
 * @group Unit
 * @group Fido2
 */
class EntityTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialUserEntityCanBeCreatedAndValueAccessed()
    {
        $user = new PublicKeyCredentialUserEntity('name', 'icon', 'id', 'display_name');

        static::assertEquals('name', $user->getName());
        static::assertEquals('display_name', $user->getDisplayName());
        static::assertEquals('icon', $user->getIcon());
        static::assertEquals('id', $user->getId());
        static::assertEquals('{"name":"name","icon":"icon","id":"aWQ=","displayName":"display_name"}', \Safe\json_encode($user));
    }

    /**
     * @test
     */
    public function anPublicKeyCredentialRpEntityCanBeCreatedAndValueAccessed()
    {
        $rp = new PublicKeyCredentialRpEntity('name', 'icon', 'id');

        static::assertEquals('name', $rp->getName());
        static::assertEquals('icon', $rp->getIcon());
        static::assertEquals('id', $rp->getId());
        static::assertEquals('{"name":"name","icon":"icon","id":"id"}', \Safe\json_encode($rp));
    }
}
