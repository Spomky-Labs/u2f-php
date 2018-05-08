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

use CBOR\CBORObject;

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
     * @var null|CBORObject
     */
    private $credentialPublicKey;

    /**
     * AttestedCredentialData constructor.
     *
     * @param string          $aaguid
     * @param string          $credentialId
     * @param null|CBORObject $credentialPublicKey
     */
    public function __construct(string $aaguid, string $credentialId, ?CBORObject $credentialPublicKey)
    {
        $this->aaguid = $aaguid;
        $this->credentialId = $credentialId;
        $this->credentialPublicKey = $credentialPublicKey;
    }

    /**
     * @return string
     */
    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    /**
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    /**
     * @return null|CBORObject
     */
    public function getCredentialPublicKey(): ?CBORObject
    {
        return $this->credentialPublicKey;
    }
}
