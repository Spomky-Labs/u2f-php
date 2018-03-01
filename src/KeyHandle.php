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

namespace U2FAuthentication;

class KeyHandle implements \JsonSerializable
{
    /**
     * @var string
     */
    private $value;

    /**
     * KeyHandle constructor.
     *
     * @param string $keyHandle
     */
    private function __construct(string $keyHandle)
    {
        $this->value = $keyHandle;
    }

    /**
     * @param string $keyHandle
     *
     * @return KeyHandle
     */
    public static function create(string $keyHandle): KeyHandle
    {
        return new self($keyHandle);
    }

    /**
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): string
    {
        return $this->value;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->value;
    }
}
