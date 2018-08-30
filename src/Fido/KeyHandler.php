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

namespace U2FAuthentication\Fido;

class KeyHandler implements \JsonSerializable
{
    /**
     * @var string
     */
    private $value;

    /**
     * KeyHandle constructor.
     */
    private function __construct(string $keyHandle)
    {
        $this->value = $keyHandle;
    }

    /**
     * @return KeyHandler
     */
    public static function create(string $keyHandle): self
    {
        return new self($keyHandle);
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function jsonSerialize(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
