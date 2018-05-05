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
use U2FAuthentication\Fido\PublicKey;

/**
 * @group Unit
 */
final class PublicKeyTest extends TestCase
{
    /**
     * @test
     */
    public function aPublicKeyCanBeCreatedAndSerialized()
    {
        $key = PublicKey::create(
            'foo'
        );

        self::assertEquals('foo', $key->getValue());
        self::assertEquals('foo', $key->jsonSerialize());
        self::assertEquals('foo', $key->__toString());
    }
}
