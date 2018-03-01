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
     *
     * @param string $rawData
     *
     * @param array  $clientData
     */
    private function __construct(string $rawData, array $clientData)
    {
        $this->rawData = $rawData;
        foreach ($clientData as $k => $v) {
            $this->$k = $v;
        }
    }

    /**
     * @param string $clientData
     * @return ClientData
     */
    public static function create(string $clientData): ClientData
    {
        $rawData = Base64Url::decode($clientData);
        if (!is_string($rawData)) {
            throw new \InvalidArgumentException('Invalid client data.');
        }
        $clientData = json_decode($rawData, true);
        if (!is_array($clientData)) {
            throw new \InvalidArgumentException('Invalid client data.');
        }

        $diff = array_diff_key(get_class_vars(self::class),$clientData);
        unset($diff['rawData']);
        if (!empty($diff)) {
            throw new \InvalidArgumentException('Invalid client data.');
        }

        return new self($rawData, $clientData);
    }

    /**
     * @return string
     */
    public function getRawData(): string
    {
        return $this->rawData;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->typ;
    }

    /**
     * @return string
     */
    public function getChallenge(): string
    {
        return Base64Url::decode($this->challenge);
    }

    /**
     * @return string
     */
    public function getOrigin(): string
    {
        return $this->origin;
    }

    /**
     * @return string
     */
    public function getChannelIdPublicKey(): string
    {
        return $this->cid_pubkey;
    }
}
