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

use Base64Url\Base64Url;

class TokenBinding
{
    public const TOKEN_BINDING_STATUS_PRESENT = 'present';
    public const TOKEN_BINDING_STATUS_SUPPORTED = 'supported';
    public const TOKEN_BINDING_STATUS_NOT_SUPPORTED = 'not-supported';

    private $status;

    private $id;

    public function __construct(string $status, ?string $id)
    {
        if (self::TOKEN_BINDING_STATUS_PRESENT === $status && !$id) {
            throw new \InvalidArgumentException('The member "is" is required when status is "present"');
        }
        $this->status = $status;
        $this->id = $id;
    }

    public static function createFormJson(array $json): self
    {
        if (!array_key_exists('status', $json)) {
            throw new \InvalidArgumentException('The member "status" is required');
        }
        $status = $json['status'];
        $id = array_key_exists('id', $json) ? Base64Url::decode($json['id']) : null;

        return new self($status, $id);
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getId(): ?string
    {
        return $this->id;
    }
}
