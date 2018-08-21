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

use Base64Url\Base64Url;

class ClientData
{
    /**
     * @var string
     */
    private $rawData;

    /**
     * @var string
     */
    private $typ;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var string
     */
    private $origin;

    /**
     * @var string
     */
    private $cid_pubkey;

    /**
     * ClientData constructor.
     */
    private function __construct(string $rawData, array $clientData)
    {
        $this->rawData = $rawData;
        foreach ($clientData as $k => $v) {
            $this->$k = $v;
        }
    }

    /**
     * @return ClientData
     */
    public static function create(string $clientData): self
    {
        $rawData = Base64Url::decode($clientData);
        $clientData = json_decode($rawData, true);
        if (!\is_array($clientData)) {
            throw new \InvalidArgumentException('Invalid client data.');
        }

        $diff = array_diff_key(get_class_vars(self::class), $clientData);
        unset($diff['rawData'], $diff['cid_pubkey']);

        if (!empty($diff)) {
            throw new \InvalidArgumentException('Invalid client data.');
        }

        return new self($rawData, $clientData);
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }

    public function getType(): string
    {
        return $this->typ;
    }

    public function getChallenge(): string
    {
        return Base64Url::decode($this->challenge);
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    public function getChannelIdPublicKey(): string
    {
        return $this->cid_pubkey;
    }
}
