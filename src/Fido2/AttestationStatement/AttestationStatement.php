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

class AttestationStatement
{
    /**
     * @var
     */
    private $fmt;

    /**
     * @var array
     */
    private $attStmt;

    public function __construct($fmt, array $attStmt)
    {
        $this->fmt = $fmt;
        $this->attStmt = $attStmt;
    }

    public function getFmt()
    {
        return $this->fmt;
    }

    public function getAttStmt(): array
    {
        return $this->attStmt;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->attStmt);
    }

    public function get(string $key)
    {
        if (!$this->has($key)) {
            throw new \InvalidArgumentException(sprintf('The attestation statement has no key "%s".', $key));
        }

        return $this->attStmt[$key];
    }
}
