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

use U2FAuthentication\Fido2\AttestationStatement\AttestationObject;

class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    /**
     * @var AttestationObject
     */
    private $attestationObject;

    public function __construct(CollectedClientData $clientDataJSON, AttestationObject $attestationObject)
    {
        parent::__construct($clientDataJSON);
        $this->attestationObject = $attestationObject;
    }

    public function getAttestationObject(): AttestationObject
    {
        return $this->attestationObject;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'clientDataJSON' => $this->getClientDataJSON(),
            'attestationObject' => $this->attestationObject,
        ];
    }
}
