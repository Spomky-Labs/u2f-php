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

class AuthenticationExtensionsClientOutputs
{
    /**
     * @var mixed[]
     */
    private $extensions = [];

    public function add(AuthenticationExtensionsClient $extension)
    {
        $this->extensions[$extension->getName()] = $extension->getValue();
    }

    public function jsonSerialize()
    {
        return $this->extensions;
    }
}
