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
    private const PROTOCOL_VERSION = 'U2F_V2';

    /**
     * @var string
     */
    private $applicationId;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var RegisteredKey[]
     */
    private $registeredKeys = [];

    /**
     * RegistrationRequest constructor.
     *
     * @param string          $applicationId
     * @param RegisteredKey[] $registeredKeys
     *
     * @throws \Exception
     */
    private function __construct(string $applicationId, array $registeredKeys = [])
    {
        $this->applicationId = $applicationId;
        $this->challenge = random_bytes(32);
        foreach ($registeredKeys as $registeredKey) {
            if (!$registeredKey instanceof RegisteredKey) {
                throw new \InvalidArgumentException('Invalid registered keys list.');
            }
            $this->registeredKeys[Base64Url::encode($registeredKey->getKeyHandler())] = $registeredKey;
        }
    }

    /**
     * @param string $applicationId
     *
     * @throws \Exception
     *
     * @return RegistrationRequest
     */
    public static function create(string $applicationId): self
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
     * @return RegisteredKey[]
     */
    public function getRegisteredKeys(): array
    {
        return $this->registeredKeys;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'appId'            => $this->applicationId,
            'registerRequests' => [
                ['version'   => self::PROTOCOL_VERSION, 'challenge' => Base64Url::encode($this->challenge)],
            ],
            'registeredKeys' => $this->registeredKeys,
        ];
    }
}
