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

use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\CollectedClientData;

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

    public function isValid(AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData, CollectedClientData $collectedClientData): bool
    {
        $fmt = $attestationStatement->getFmt();
        if (!array_key_exists($fmt, $this->attestationStatementSupports)) {
            throw new \InvalidArgumentException(sprintf('The attestation format "%s" is not supported.', $fmt));
        }

        return $this->attestationStatementSupports[$fmt]->isValid($attestationStatement, $authenticatorData, $collectedClientData);
    }
}
