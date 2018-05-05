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
     * @var string
     */
    private $clientDataJSON;

    /**
     * AuthenticatorResponse constructor.
     *
     * @param string $clientDataJSON
     */
    public function __construct(string $clientDataJSON)
    {
        $this->clientDataJSON = $clientDataJSON;
    }

    /**
     * @return string
     */
    public function getClientDataJSON(): string
    {
        return $this->clientDataJSON;
    }
}
