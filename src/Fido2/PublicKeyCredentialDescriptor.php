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

class PublicKeyCredentialDescriptor implements \JsonSerializable
{
    public const PUBLIC_KEY_CREDENTIAL_TYPE_PUBLIC_KEY = 'public-key';

    public const AUTHENTICATOR_TRANSPORT_USB = 'usb';
    public const AUTHENTICATOR_TRANSPORT_NFC = 'nfc';
    public const AUTHENTICATOR_TRANSPORT_BLE = 'ble';

    /**
     * @var string
     */
    private $type;

    /**
     * @var string
     */
    private $id;

    /**
     * @var string[]
     */
    private $transports;

    /**
     * PublicKeyCredentialDescriptor constructor.
     *
     * @param string   $type
     * @param string   $id
     * @param string[] $transports
     */
    public function __construct(string $type, string $id, array $transports = [])
    {
        $this->type = $type;
        $this->id = $id;
        $this->transports = $transports;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        $json = [
            'type'       => $this->type,
            'id'         => $this->splitId(),
        ];
        if ($this->transports) {
            $json['transports'] = $this->transports;
        }

        return $json;
    }

    /**
     * @return int[]
     */
    private function splitId(): array
    {
        $result = [];
        $split = str_split($this->id);
        foreach ($split as $char) {
            $result[] = ord($char);
        }

        return $result;
    }
}
