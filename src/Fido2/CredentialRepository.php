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

namespace U2FAuthentication\Fido2;

use CBOR\CBORObject;

interface CredentialRepository
{
    public function hasCredential(string $credentialId): bool;

    public function getCredentialPublicKey(string $credentialId): CBORObject;

    public function getCredentialCounter(string $credentialId): int;

    public function updateCredentialCounter(string $credentialId, int $newCounter): void;
}
