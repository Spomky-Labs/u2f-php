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

namespace U2FAuthentication\Fido2;

class AttestedCredentialData
{
    /**
     * @var string
     */
    private $aaguid;

    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var null|array
     */
    private $credentialPublicKey;

    /**
     * AttestedCredentialData constructor.
     *
     * @param null|array $credentialPublicKey
     */
    public function __construct(string $aaguid, string $credentialId, array $credentialPublicKey)
    {
        $this->aaguid = $aaguid;
        $this->credentialId = $credentialId;
        $this->credentialPublicKey = $credentialPublicKey;
    }

    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getCredentialPublicKey(): ?array
    {
        return $this->credentialPublicKey;
    }
}
