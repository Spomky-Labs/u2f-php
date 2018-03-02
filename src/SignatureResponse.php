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

class SignatureResponse
{
    /**
     * @var ClientData
     */
    private $clientData;

    /**
     * @var KeyHandle
     */
    private $keyHandle;

    /**
     * @var bool
     */
    private $userPresence;

    /**
     * @var string
     */
    private $userPresenceByte;

    /**
     * @var int
     */
    private $counter;

    /**
     * @var string
     */
    private $counterBytes;

    /**
     * @var string
     */
    private $signature;

    /**
     * RegistrationChallengeMiddleware constructor.
     *
     * @param array $data
     */
    private function __construct(array $data)
    {
        if (array_key_exists('errorCode', $data)) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $this->keyHandle = $this->retrieveKeyHandle($data);
        $this->clientData = $this->retrieveClientData($data);
        if ('navigator.id.getAssertion' !== $this->clientData->getType()) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        list($this->userPresence, $this->userPresenceByte, $this->counter, $this->counterBytes, $this->signature) = $this->extractSignatureData($data);
    }

    /**
     * @param array $data
     *
     * @return SignatureResponse
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    /**
     * @return ClientData
     */
    public function getClientData(): ClientData
    {
        return $this->clientData;
    }

    /**
     * @return KeyHandle
     */
    public function getKeyHandle(): KeyHandle
    {
        return $this->keyHandle;
    }

    /**
     * @return bool
     */
    public function isUserPresence(): bool
    {
        return $this->userPresence;
    }

    /**
     * @return int
     */
    public function getCounter(): int
    {
        return $this->counter;
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
     * @throws \InvalidArgumentException
     *
     * @return KeyHandle
     */
    private function retrieveKeyHandle(array $data): KeyHandle
    {
        if (!array_key_exists('keyHandle', $data) || !is_string($data['keyHandle'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        return KeyHandle::create(Base64Url::decode($data['keyHandle']));
    }

    /**
     * @param array $data
     *
     * @throws \InvalidArgumentException
     *
     * @return ClientData
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
     *
     * @return array
     */
    private function extractSignatureData(array $data): array
    {
        if (!array_key_exists('signatureData', $data) || !is_string($data['signatureData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $stream = fopen('php://memory', 'r+');
        $signatureData = Base64Url::decode($data['signatureData']);
        fwrite($stream, $signatureData);
        rewind($stream);

        $userPresenceByte = fread($stream, 1);
        if (!is_string($userPresenceByte)) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        $userPresence = (bool) ord($userPresenceByte);

        $counterBytes = fread($stream, 4);
        if (!is_string($counterBytes)) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        $counter = unpack('Nctr', $counterBytes)['ctr'];
        $signature = '';
        while (!feof($stream)) {
            $tmp = fread($stream, 1024);
            if (!is_string($tmp)) {
                throw new \InvalidArgumentException('Invalid response.');
            }
            $signature .= $tmp;
        }

        return [
            $userPresence,
            $userPresenceByte,
            $counter,
            $counterBytes,
            $signature,
        ];
    }

    /**
     * @param SignatureRequest $request
     * @param int|null         $currentCounter
     *
     * @return bool
     */
    public function isValid(SignatureRequest $request, ?int $currentCounter = null): bool
    {
        if (!hash_equals($request->getChallenge(), $this->clientData->getChallenge())) {
            return false;
        }
        if (!hash_equals($request->getApplicationId(), $this->clientData->getOrigin())) {
            return false;
        }

        if ($currentCounter !== null && $currentCounter >= $this->counter) {
            return false;
        }

        $dataToVerify = hash('sha256', $this->clientData->getOrigin(), true);
        $dataToVerify .= $this->userPresenceByte;
        $dataToVerify .= $this->counterBytes;
        $dataToVerify .= hash('sha256', $this->clientData->getRawData(), true);

        $registeredKey = $request->getRegisteredKey($this->keyHandle);

        return openssl_verify($dataToVerify, $this->signature, $registeredKey->getPublicKeyAsPem(), 'sha256') === 1;
    }
}
