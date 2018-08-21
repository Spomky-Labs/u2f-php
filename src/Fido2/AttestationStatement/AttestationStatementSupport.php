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

namespace U2FAuthentication\Fido2\AttestationStatement;

use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\CollectedClientData;

interface AttestationStatementSupport
{
    public function name(): string;

    public function isValid(AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData, CollectedClientData $collectedClientData): bool;
}
