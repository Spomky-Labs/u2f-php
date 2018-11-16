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
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClient;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @group Unit
 * @group Fido2
 */
class AuthenticationExtensionsClientTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticationExtensionsClientCanBeCreatedAndValueAccessed()
    {
        $extension = new AuthenticationExtensionsClient('name', ['value']);

        static::assertEquals('name', $extension->name());
        static::assertEquals(['value'], $extension->value());
        static::assertEquals('["value"]', \Safe\json_encode($extension->value()));
    }

    /**
     * @test
     */
    public function theAuthenticationExtensionsClientInputsCanManageExtensions()
    {
        $extension = new AuthenticationExtensionsClient('name', ['value']);

        $inputs = new AuthenticationExtensionsClientInputs();
        $inputs->add($extension);

        static::assertEquals(1, $inputs->count());
        static::assertEquals('{"name":["value"]}', \Safe\json_encode($inputs));
        foreach ($inputs as $k => $input) {
            static::assertInstanceOf(AuthenticationExtensionsClient::class, $input);
        }
    }

    /**
     * @test
     */
    public function theAuthenticationExtensionsClientOutputsCanManageExtensions()
    {
        $extension = new AuthenticationExtensionsClient('name', ['value']);

        $inputs = new AuthenticationExtensionsClientOutputs();
        $inputs->add($extension);

        static::assertEquals(1, $inputs->count());
        static::assertEquals('{"name":["value"]}', \Safe\json_encode($inputs));
        foreach ($inputs as $k => $input) {
            static::assertInstanceOf(AuthenticationExtensionsClient::class, $input);
        }
    }
}
