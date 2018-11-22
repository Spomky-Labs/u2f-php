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
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;

/**
 * @group Unit
 * @group Fido2
 *
 * @covers \U2FAuthentication\Fido2\PublicKeyCredentialParameters
 */
class PublicKeyCredentialParametersTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialParametersCanBeCreatedAndValueAccessed()
    {
        $parameters = new PublicKeyCredentialParameters('type', 100);

        static::assertEquals('type', $parameters->getType());
        static::assertEquals(100, $parameters->getAlg());
        static::assertEquals('{"type":"type","alg":100}', \Safe\json_encode($parameters));
    }
}
