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

namespace U2FAuthentication\Fido2\AttestationStatement;

use Assert\Assertion;

class AttestationStatement
{
    private $fmt;

    private $attStmt;

    public function __construct(string $fmt, array $attStmt)
    {
        $this->fmt = $fmt;
        $this->attStmt = $attStmt;
    }

    public function getFmt(): string
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
        Assertion::true($this->has($key), \Safe\sprintf('The attestation statement has no key "%s".', $key));

        return $this->attStmt[$key];
    }
}
