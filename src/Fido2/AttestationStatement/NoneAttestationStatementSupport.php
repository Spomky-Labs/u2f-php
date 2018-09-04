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

final class NoneAttestationStatementSupport implements AttestationStatementSupport
{
    public function name(): string
    {
        return 'none';
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        return empty($attestationStatement->getAttStmt());
    }
}
