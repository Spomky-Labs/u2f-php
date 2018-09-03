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
    public function hasCredentialId(string $credentialId): bool;

    public function getCredentialId(string $credentialId): AttestedCredentialData;

    public function hasCredentialPublicKey(string $credentialId): bool;

    public function getCredentialPublicKey(string $credentialId): CBORObject;
}
