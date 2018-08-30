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

    public function __construct(string $rawData, array $data)
    {
        $this->rawData = $rawData;
        $this->data = $data;
    }

    public static function createFormJson(string $data): self
    {
        $json = json_decode(Base64Url::decode($data), true);

        if (!array_key_exists('type', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('challenge', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('origin', $json)) {
            throw new \InvalidArgumentException();
        }
        if (array_key_exists('tokenBinding', $json)) {
            $json['tokenBinding'] = TokenBinding::createFormJson($json['tokenBinding']);
        } else {
            $json['tokenBinding'] = null;
        }

        return new self(Base64Url::decode($data), $json);
    }

    public function getType(): string
    {
        return $this->data['type'];
    }

    public function getChallenge(): string
    {
        return $this->data['challenge'];
    }

    public function getOrigin(): string
    {
        return $this->data['origin'];
    }

    public function getTokenBinding(): ?TokenBinding
    {
        return $this->data['tokenBinding'];
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(string $key)
    {
        if (!$this->has($key)) {
            throw new \InvalidArgumentException(sprintf('The collected client data has no key "%s".', $key));
        }

        return $this->data[$key];
    }
}
