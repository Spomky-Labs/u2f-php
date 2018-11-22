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
use U2FAuthentication\CertificateToolbox;

/**
 * @group Unit
 * @group Fido2
 */
class CertificateChainCheckerTest extends TestCase
{
    /**
     * @test
     *
     * @use \U2FAuthentication\Fido2\CertificateToolbox::checkChain
     */
    public function anCertificateChainCheckerCanBeCreatedAndValueAccessed()
    {
        $x5c = [
            \Safe\file_get_contents(__DIR__.'/../../certificates/chain/1.der'),
            \Safe\file_get_contents(__DIR__.'/../../certificates/chain/2.der'),
            \Safe\file_get_contents(__DIR__.'/../../certificates/chain/3.der'),
            \Safe\file_get_contents(__DIR__.'/../../certificates/chain/4.der'),
        ];

        $cert = CertificateToolbox::checkChain($x5c);
        static::assertEquals(
            \Safe\file_get_contents(__DIR__.'/../../certificates/chain/1.crt'),
            $cert
        );
    }
}
