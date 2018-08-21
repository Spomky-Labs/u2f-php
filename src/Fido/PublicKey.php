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

class PublicKey implements \JsonSerializable
{
    /**
     * @var string
     */
    private $value;

    /**
     * PublicKey constructor.
     */
    private function __construct(string $publicKey)
    {
        $this->value = $publicKey;
    }

    /**
     * @return PublicKey
     */
    public static function create(string $publicKey): self
    {
        return new self($publicKey);
    }

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

    public function __toString(): string
    {
        return $this->value;
    }
}
