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

abstract class AuthenticatorResponse implements \JsonSerializable
{
    /**
     * @var CollectedClientData
     */
    private $clientDataJSON;

    public function __construct(CollectedClientData $clientDataJSON)
    {
        $this->clientDataJSON = $clientDataJSON;
    }

    public function getClientDataJSON(): CollectedClientData
    {
        return $this->clientDataJSON;
    }
}
