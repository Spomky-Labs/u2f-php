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

class SignatureResponse
{
    /**
     * @var ClientData
     */
    private $clientData;

    /**
     * @var KeyHandler
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

    public function __construct(array $data)
    {
        if (array_key_exists('errorCode', $data) && 0 !== $data['errorCode']) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $this->keyHandle = $this->retrieveKeyHandle($data);
        $this->clientData = $this->retrieveClientData($data);
        if ('navigator.id.getAssertion' !== $this->clientData->getType()) {
            throw new \InvalidArgumentException('Invalid response.');
        }
        list($this->userPresence, $this->userPresenceByte, $this->counter, $this->counterBytes, $this->signature) = $this->extractSignatureData($data);
    }

    public function getClientData(): ClientData
    {
        return $this->clientData;
    }

    public function getKeyHandle(): KeyHandler
    {
        return $this->keyHandle;
    }

    public function isUserPresent(): bool
    {
        return $this->userPresence;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    private function retrieveKeyHandle(array $data): KeyHandler
    {
        if (!array_key_exists('keyHandle', $data) || !\is_string($data['keyHandle'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        return new KeyHandler(Base64Url::decode($data['keyHandle']));
    }

    private function retrieveClientData(array $data): ClientData
    {
        if (!array_key_exists('clientData', $data) || !\is_string($data['clientData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        return new ClientData($data['clientData']);
    }

    private function extractSignatureData(array $data): array
    {
        if (!array_key_exists('signatureData', $data) || !\is_string($data['signatureData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $stream = \Safe\fopen('php://memory', 'r+');
        $signatureData = Base64Url::decode($data['signatureData']);
        \Safe\fwrite($stream, $signatureData);
        \Safe\rewind($stream);

        $userPresenceByte = \Safe\fread($stream, 1);
        if (1 !== mb_strlen($userPresenceByte, '8bit')) {
            \Safe\fclose($stream);

            throw new \InvalidArgumentException('Invalid response.');
        }
        $userPresence = (bool) \ord($userPresenceByte);

        $counterBytes = \Safe\fread($stream, 4);
        if (4 !== mb_strlen($counterBytes, '8bit')) {
            \Safe\fclose($stream);

            throw new \InvalidArgumentException('Invalid response.');
        }
        $counter = unpack('Nctr', $counterBytes)['ctr'];
        $signature = '';
        while (!feof($stream)) {
            $signature .= \Safe\fread($stream, 1024);
        }
        \Safe\fclose($stream);

        return [
            $userPresence,
            $userPresenceByte,
            $counter,
            $counterBytes,
            $signature,
        ];
    }

    public function isValid(SignatureRequest $request, ?int $currentCounter = null): bool
    {
        if (!hash_equals($request->getChallenge(), $this->clientData->getChallenge())) {
            return false;
        }
        if (!hash_equals($request->getApplicationId(), $this->clientData->getOrigin())) {
            return false;
        }

        if (null !== $currentCounter && $currentCounter >= $this->counter) {
            return false;
        }

        $dataToVerify = hash('sha256', $this->clientData->getOrigin(), true);
        $dataToVerify .= $this->userPresenceByte;
        $dataToVerify .= $this->counterBytes;
        $dataToVerify .= hash('sha256', $this->clientData->getRawData(), true);

        $registeredKey = $request->getRegisteredKey($this->keyHandle);

        return 1 === openssl_verify($dataToVerify, $this->signature, $registeredKey->getPublicKeyAsPem(), OPENSSL_ALGO_SHA256);
    }
}
