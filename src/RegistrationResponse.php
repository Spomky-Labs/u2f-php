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

class RegistrationResponse
{
    private const SUPPORTED_PROTOCOL_VERSIONS = ['U2F_V2'];
    private const PUBLIC_KEY_LENGTH = 65;
    private const CERTIFICATES_HASHES = [
        '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
        'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
        '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
        'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
        '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
        'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511'
    ];

    /**
     * @var ClientData
     */
    private $clientData;

    /**
     * @var RegisteredKey
     */
    private $registeredKey;

    /**
     * @var string
     */
    private $signature;

    /**
     * RegistrationChallengeMiddleware constructor.
     *
     * @param string $challengeResponse
     */
    private function __construct(string $challengeResponse)
    {
        $json = json_decode($challengeResponse, true);
        if (!is_array($json)) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        if (array_key_exists('errorCode', $json)) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $this->checkVersion($json);
        $clientData = $this->retrieveClientData($json);
        if ('navigator.id.finishEnrollment' !== $clientData->getType()) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        $this->checkChallenge($json, $clientData);
        list($publicKey, $keyHandle, $pemCert, $signature) = $this->extractKeyData($json);

        $this->clientData = $clientData;
        $this->registeredKey = RegisteredKey::create($json['version'], $keyHandle, $publicKey, $pemCert);
        $this->signature = $signature;
    }

    /**
     * @param string $challengeResponse
     *
     * @return RegistrationResponse
     */
    public static function create(string $challengeResponse): RegistrationResponse
    {
        return new self($challengeResponse);
    }

    /**
     * @return ClientData
     */
    public function getClientData(): ClientData
    {
        return $this->clientData;
    }

    /**
     * @return RegisteredKey
     */
    public function getRegisteredKey(): RegisteredKey
    {
        return $this->registeredKey;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @param array $data
     *
     * @return ClientData
     *
     * @throws \InvalidArgumentException
     */
    private function retrieveClientData(array $data): ClientData
    {
        if (!array_key_exists('clientData', $data) || !is_string($data['clientData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        return ClientData::create($data['clientData']);
    }

    /**
     * @param array $data
     *
     * @throws \InvalidArgumentException
     */
    private function checkVersion(array $data): void
    {
        if (!array_key_exists('version', $data) || !is_string($data['version'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        if (!in_array($data['version'], self::SUPPORTED_PROTOCOL_VERSIONS)) {
            throw new \InvalidArgumentException('Unsupported protocol version.');
        }
    }

    /**
     * @param array      $data
     * @param ClientData $clientData
     *
     * @throws \InvalidArgumentException
     */
    private function checkChallenge(array $data, ClientData $clientData): void
    {
        if (!array_key_exists('challenge', $data) || !is_string($data['challenge'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        if (!hash_equals(Base64Url::decode($data['challenge']), $clientData->getChallenge())) {
            throw new \InvalidArgumentException('Invalid response.');
        }
    }

    /**
     * @param array $data
     *
     * @return array
     *
     * @throws \InvalidArgumentException
     */
    private function extractKeyData(array $data): array
    {
        if (!array_key_exists('registrationData', $data) || !is_string($data['registrationData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        $stream = fopen('php://memory','r+');
        $registrationData = Base64Url::decode($data['registrationData']);
        fwrite($stream, $registrationData);
        rewind($stream);

        $reservedByte = fread($stream, 1);
        if (!is_string($reservedByte ) || "\x05" !== $reservedByte) { // First byte is reserved with value x05
            throw new \InvalidArgumentException('Invalid response.');
        }

        $publicKey = fread($stream, self::PUBLIC_KEY_LENGTH);
        if (!is_string($publicKey)) { // Bytes of the public key
            throw new \InvalidArgumentException('Invalid response.');
        }
        $keyHandleLength = fread($stream, 1);
        if (!is_string($keyHandleLength)) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $keyHandle = fread($stream, ord($keyHandleLength));
        if (!is_string($keyHandle)) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $certHeader = fread($stream, 4);
        if (!is_string($certHeader)) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $highOrder = ord($certHeader[2])<<8;
        $lowOrder = ord($certHeader[3]);
        $certLength = $highOrder + $lowOrder;

        $certBody = fread($stream, $certLength);
        $derCertificate = $this->unusedBytesFix($certHeader.$certBody);
        $pemCert  = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        $signature = '';
        while (!feof($stream)) {
            $tmp = fread($stream, 1024);
            if (!is_string($tmp)) {
                throw new \InvalidArgumentException('Invalid response.');
            }
            $signature .= $tmp;
        }

        return [
            PublicKey::create($publicKey),
            KeyHandle::create($keyHandle),
            $pemCert,
            $signature,
        ];
    }

    /**
     * @param string $derCertificate
     *
     * @return string
     */
    private function unusedBytesFix(string $derCertificate): string
    {
        $certificateHash = hash('sha256', $derCertificate);
        if(in_array($certificateHash, self::CERTIFICATES_HASHES)) {
            $derCertificate[mb_strlen($derCertificate, '8bit') - 257] = "\0";
        }
        return $derCertificate;
    }

    /**
     * @param RegistrationRequest $challenge
     * @param string[]              $attestationCertificates
     *
     * @return bool
     */
    public function isValid(RegistrationRequest $challenge, array $attestationCertificates = []): bool
    {
        if (!hash_equals($challenge->getChallenge(), $this->clientData->getChallenge())) {
            return false;
        }
        if (!hash_equals($challenge->getApplicationId(), $this->clientData->getOrigin())) {
            return false;
        }

        if(!empty($attestationCertificates) && openssl_x509_checkpurpose($this->registeredKey->getAttestationCertificate(), X509_PURPOSE_ANY, $attestationCertificates) !== true) {
            return false;
        }

        $dataToVerify  = "\0";
        $dataToVerify .= hash('sha256', $this->clientData->getOrigin(), true);
        $dataToVerify .= hash('sha256', $this->clientData->getRawData(), true);
        $dataToVerify .= $this->registeredKey->getKeyHandler();
        $dataToVerify .= $this->registeredKey->getPublicKey();

        return openssl_verify($dataToVerify, $this->signature, $this->registeredKey->getAttestationCertificate(), 'sha256') === 1;
    }
}
