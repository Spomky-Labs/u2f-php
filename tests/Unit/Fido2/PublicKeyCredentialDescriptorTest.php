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
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \U2FAuthentication\Fido2\PublicKeyCredentialDescriptor
 */
class PublicKeyCredentialDescriptorTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialDescriptorCanBeCreatedAndValueAccessed()
    {
        $descriptor = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);

        static::assertEquals('type', $descriptor->getType());
        static::assertEquals('id', $descriptor->getId());
        static::assertEquals(['transport'], $descriptor->getTransports());
        static::assertEquals('{"type":"type","id":"aWQ=","transports":["transport"]}', \Safe\json_encode($descriptor));

        $created = PublicKeyCredentialDescriptor::createFromJson('{"type":"type","id":"aWQ=","transports":["transport"]}');
        static::assertEquals($descriptor, $created);
    }
}
