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

class TokenBinding
{
    public const TOKEN_BINDING_STATUS_PRESENT = 'present';
    public const TOKEN_BINDING_STATUS_SUPPORTED = 'supported';
    public const TOKEN_BINDING_STATUS_NOT_SUPPORTED = 'not-supported';
    /**
     * @var string
     */
    private $status;

    /**
     * @var null|string
     */
    private $id;

    /**
     * TokenBinding constructor.
     *
     * @param string      $status
     * @param null|string $id
     */
    public function __construct(string $status, ?string $id)
    {
        $this->status = $status;
        $this->id = $id;
    }

    /**
     * @param array $json
     *
     * @return TokenBinding
     */
    public static function createFormJson(array $json): self
    {
        if (!array_key_exists('status', $json)) {
            throw new \InvalidArgumentException();
        }

        return new self(
            $json['status'],
            array_key_exists('id', $json) ? $json['status'] : null
        );
    }

    /**
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * @return null|string
     */
    public function getId(): ?string
    {
        return $this->id;
    }
}
