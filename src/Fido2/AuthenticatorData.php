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

use CBOR\CBORObject;

class AuthenticatorData
{
    private $rpIdHash;

    private $flags;

    private $signCount;

    private $attestedCredentialData;

    private $extensions;

    private const FLAG_UP = 0b00000001;
    private const FLAG_RFU1 = 0b00000010;
    private const FLAG_UV = 0b00000100;
    private const FLAG_RFU2 = 0b00111000;
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;

    public function __construct(string $rpIdHash, string $flags, int $signCount, AttestedCredentialData $attestedCredentialData, ?CBORObject $extensions)
    {
        $this->rpIdHash = $rpIdHash;
        $this->flags = $flags;
        $this->signCount = $signCount;
        $this->attestedCredentialData = $attestedCredentialData;
        $this->extensions = $extensions;
    }

    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    public function isUserPresent(): bool
    {
        return \ord($this->flags) & self::FLAG_UP ? true : false;
    }

    public function isUserVerified(): bool
    {
        return \ord($this->flags) & self::FLAG_UV ? true : false;
    }

    public function hasAttestedCredentialData(): bool
    {
        return \ord($this->flags) & self::FLAG_AT ? true : false;
    }

    public function hasExtensions(): bool
    {
        return \ord($this->flags) & self::FLAG_ED ? true : false;
    }

    public function getReservedForFutureUse1(): int
    {
        return \ord($this->flags) & self::FLAG_RFU1;
    }

    public function getReservedForFutureUse2(): int
    {
        return \ord($this->flags) & self::FLAG_RFU2;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    public function getExtensions()
    {
        return $this->extensions;
    }
}
