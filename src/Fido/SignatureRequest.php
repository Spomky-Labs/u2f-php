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

namespace U2FAuthentication\Fido;

use Base64Url\Base64Url;

class SignatureRequest implements \JsonSerializable
{
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
     * SignatureRequest constructor.
     *
     * @param RegisteredKey[] $registeredKeys
     *
     * @throws \Exception
     */
    private function __construct(string $applicationId, array $registeredKeys)
    {
        $this->applicationId = $applicationId;
        foreach ($registeredKeys as $registeredKey) {
            if (!$registeredKey instanceof RegisteredKey) {
                throw new \InvalidArgumentException('Invalid registered keys list.');
            }
            $this->registeredKeys[Base64Url::encode((string) $registeredKey->getKeyHandler())] = $registeredKey;
        }
        $this->challenge = random_bytes(32);
    }

    /**
     * @param RegisteredKey[] $registeredKeys
     *
     * @throws \Exception
     *
     * @return SignatureRequest
     */
    public static function create(string $applicationId, array $registeredKeys): self
    {
        return new self($applicationId, $registeredKeys);
    }

    public function addRegisteredKey(RegisteredKey $registeredKey): void
    {
        $this->registeredKeys[Base64Url::encode((string) $registeredKey->getKeyHandler())] = $registeredKey;
    }

    public function hasRegisteredKey(KeyHandler $keyHandle): bool
    {
        return array_key_exists(Base64Url::encode($keyHandle->getValue()), $this->registeredKeys);
    }

    public function getRegisteredKey(KeyHandler $keyHandle): RegisteredKey
    {
        if (!$this->hasRegisteredKey($keyHandle)) {
            throw new \InvalidArgumentException('Unsupported key handle.');
        }

        return $this->registeredKeys[Base64Url::encode($keyHandle->getValue())];
    }

    public function getApplicationId(): string
    {
        return $this->applicationId;
    }

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
            'appId'          => $this->applicationId,
            'challenge'      => Base64Url::encode($this->challenge),
            'registeredKeys' => array_values($this->registeredKeys),
        ];
    }
}
