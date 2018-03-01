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

use Base64Url\Base64Url;

class RegistrationRequest implements \JsonSerializable
{
    private const PROTOCOL_VERSION = "U2F_V2";

    /**
     * @var string
     */
    private $applicationId;

    /**
     * @var string
     */
    private $challenge;

    /**
     * RegistrationRequest constructor.
     *
     * @param string $applicationId
     *
     * @throws \Exception
     */
    private function __construct(string $applicationId)
    {
        $this->applicationId = $applicationId;
        $this->challenge = random_bytes(32);
    }

    /**
     * @param string $applicationId
     *
     * @return RegistrationRequest
     *
     * @throws \Exception
     */
    public static function create(string $applicationId): RegistrationRequest
    {
        return new self($applicationId);
    }

    /**
     * @return string
     */
    public function getApplicationId(): string
    {
        return $this->applicationId;
    }

    /**
     * @return string
     */
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'version' => self::PROTOCOL_VERSION,
            'challenge' => Base64Url::encode($this->challenge),
            'appId' => $this->applicationId,
        ];
    }
}
