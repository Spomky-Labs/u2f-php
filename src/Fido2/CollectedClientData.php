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

class CollectedClientData
{
    private $rawData;
    private $data;
    private $type;
    private $challenge;
    private $origin;
    private $tokenBinding;

    public function __construct(string $rawData, array $data)
    {
        $validators = $this->dataValidators();
        foreach ($validators as $parameter => $validator) {
            $this->$parameter = $validator($data);
        }
        $this->rawData = $rawData;
        $this->data = $data;
    }

    public static function createFormJson(string $data): self
    {
        $rawData = Base64Url::decode($data);
        $json = \Safe\json_decode($rawData, true);
        if (\is_array($json)) {
            throw new \InvalidArgumentException('Invalid collected client data');
        }

        return new self($rawData, $json);
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    public function getTokenBinding(): ?TokenBinding
    {
        return $this->tokenBinding ? TokenBinding::createFormJson($this->tokenBinding) : null;
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }

    /**
     * @return string[]
     */
    public function all(): array
    {
        return array_keys($this->data);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(string $key)
    {
        if (!$this->has($key)) {
            throw new \InvalidArgumentException(\Safe\sprintf('The key "%s" is missing', $key));
        }

        return $this->data[$key];
    }

    /**
     * @return callable[]
     */
    private function dataValidators(): array
    {
        return [
            'type' => $this->requiredData('type'),
            'challenge' => $this->requiredData('challenge', true),
            'origin' => $this->requiredData('origin'),
            'tokenBinding' => $this->optionalData('tokenBinding'),
        ];
    }

    private function requiredData($key, bool $isB64 = false): callable
    {
        return function ($json) use ($key, $isB64) {
            if (!array_key_exists($key, $json)) {
                throw new \InvalidArgumentException(\Safe\sprintf('The key "%s" is missing', $key));
            }

            return $isB64 ? Base64Url::decode($json[$key]) : $json[$key];
        };
    }

    private function optionalData($key): callable
    {
        return function ($json) use ($key) {
            if (!array_key_exists($key, $json)) {
                return;
            }

            return $json[$key];
        };
    }
}
