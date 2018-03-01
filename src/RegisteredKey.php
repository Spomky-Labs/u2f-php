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

class RegisteredKey implements \JsonSerializable
{
    /**
     * @var string
     */
    private $version;

    /**
     * @var KeyHandle
     */
    private $keyHandler;

    /**
     * @var PublicKey
     */
    private $publicKey;

    /**
     * @var string
     */
    private $attestationCertificate;

    /**
     * RegisteredKey constructor.
     *
     * @param string    $version
     * @param KeyHandle $keyHandler
     * @param PublicKey $publicKey
     * @param string    $attestationCertificate
     */
    private function __construct(string $version, KeyHandle $keyHandler, PublicKey $publicKey, string $attestationCertificate)
    {
        $this->version = $version;
        $this->keyHandler = $keyHandler;
        $this->publicKey = $publicKey;
        $this->attestationCertificate = $attestationCertificate;
    }

    /**
     * @param string    $version
     * @param KeyHandle $keyHandler
     * @param PublicKey $publicKey
     * @param string    $certificate
     *
     * @return RegisteredKey
     */
    public static function create(string $version, KeyHandle $keyHandler, PublicKey $publicKey, string $certificate): RegisteredKey
    {
        return new self($version, $keyHandler, $publicKey, $certificate);
    }

    /**
     * @return string
     */
    public function getVersion(): string
    {
        return $this->version;
    }

    /**
     * @return KeyHandle
     */
    public function getKeyHandler(): KeyHandle
    {
        return $this->keyHandler;
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * @return string
     */
    public function getPublicKeyAsPem(): string
    {
        $der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\0".$this->publicKey;

        $pem  = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $pem;
    }

    /**
     * @return string
     */
    public function getAttestationCertificate(): string
    {
        return $this->attestationCertificate;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return [
            'version' => $this->version,
            'keyHandle' => Base64Url::encode($this->keyHandler),
        ];
    }
}
