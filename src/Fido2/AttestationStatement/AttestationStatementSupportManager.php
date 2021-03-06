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

namespace U2FAuthentication\Fido2\AttestationStatement;

use Assert\Assertion;

class AttestationStatementSupportManager
{
    /**
     * @var AttestationStatementSupport[]
     */
    private $attestationStatementSupports = [];

    public function add(AttestationStatementSupport $attestationStatementSupport)
    {
        $this->attestationStatementSupports[$attestationStatementSupport->name()] = $attestationStatementSupport;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->attestationStatementSupports);
    }

    public function get(string $name): AttestationStatementSupport
    {
        Assertion::true($this->has($name), \Safe\sprintf('The attestation statement format "%s" is not supported.', $name));

        return $this->attestationStatementSupports[$name];
    }
}
