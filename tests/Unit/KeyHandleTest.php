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
use U2FAuthentication\Fido\KeyHandler;

/**
 * @group Unit
 */
final class KeyHandleTest extends TestCase
{
    /**
     * @test
     */
    public function aKeyHandleCanBeCreatedAndSerialized()
    {
        $handle = KeyHandler::create(
            'foo'
        );

        static::assertEquals('foo', $handle->getValue());
        static::assertEquals('foo', $handle->jsonSerialize());
        static::assertEquals('foo', $handle->__toString());
    }
}
