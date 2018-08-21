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

final class NoneAttestationStatement implements AttestationStatementSupport
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData, CollectedClientData $collectedClientData): bool
    {
        return empty($attestationStatement->getAttStmt());
    }
}
