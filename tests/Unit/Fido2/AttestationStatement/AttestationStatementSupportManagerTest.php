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

namespace U2FAuthentication\Tests\Unit\Fido2\AttestationStatement;

use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;

/**
 * @group Unit
 * @group Fido2
 */
class AttestationStatementSupportManagerTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement format "bar" is not supported.
     */
    public function theAttestationFormatIsNotSupported()
    {
        $manager = new AttestationStatementSupportManager();
        $manager->get('bar');
    }
}
