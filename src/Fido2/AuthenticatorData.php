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

class AuthenticatorData
{
    /**
     * @var string
     */
    private $rpIdHash;

    /**
     * @var string
     */
    private $flags;

    /**
     * @var int
     */
    private $signCount;

    /**
     * @var null
     */
    private $attestedCredentialData;

    /**
     * @var null
     */
    private $extensions;

    private const FLAG_UP = 0b00000001;
    private const FLAG_RFU1 = 0b00000010;
    private const FLAG_UV = 0b00000100;
    private const FLAG_RFU2 = 0b00111000;
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;

    /**
     * AuthenticatorData constructor.
     *
     * @param string $rpIdHash
     * @param string $flags
     * @param int    $signCount
     * @param $attestedCredentialData
     * @param CBORObject|null $extensions
     */
    public function __construct(string $rpIdHash, string $flags, int $signCount, $attestedCredentialData, ?CBORObject $extensions)
    {
        $this->rpIdHash = $rpIdHash;
        $this->flags = $flags;
        $this->signCount = $signCount;
        $this->attestedCredentialData = $attestedCredentialData;
        $this->extensions = $extensions;
    }

    /**
     * @return string
     */
    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    /**
     * @return bool
     */
    public function isUserPresent(): bool
    {
        return ord($this->flags) & self::FLAG_UP ? true : false;
    }

    /**
     * @return bool
     */
    public function isUserVerified(): bool
    {
        return ord($this->flags) & self::FLAG_UV ? true : false;
    }

    /**
     * @return bool
     */
    public function hasAttestedCredentialData(): bool
    {
        return ord($this->flags) & self::FLAG_AT ? true : false;
    }

    /**
     * @return bool
     */
    public function hasExtensions(): bool
    {
        return ord($this->flags) & self::FLAG_ED ? true : false;
    }

    /**
     * @return int
     */
    public function getReservedForFutureUse1(): int
    {
        return ord($this->flags) & self::FLAG_RFU1;
    }

    /**
     * @return int
     */
    public function getReservedForFutureUse2(): int
    {
        return ord($this->flags) & self::FLAG_RFU2;
    }

    /**
     * @return int
     */
    public function getSignCount(): int
    {
        return $this->signCount;
    }

    /**
     * @return null
     */
    public function getAttestedCredentialData()
    {
        return $this->attestedCredentialData;
    }

    /**
     * @return null
     */
    public function getExtensions()
    {
        return $this->extensions;
    }
}
