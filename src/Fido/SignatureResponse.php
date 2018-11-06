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

    /**
     * RegistrationChallengeMiddleware constructor.
     */
    private function __construct(array $data)
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

    /**
     * @return SignatureResponse
     */
    public static function create(array $data): self
    {
        return new self($data);
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

    /**
     * @throws \InvalidArgumentException
     */
    private function retrieveKeyHandle(array $data): KeyHandler
    {
        if (!array_key_exists('keyHandle', $data) || !\is_string($data['keyHandle'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        return KeyHandler::create(Base64Url::decode($data['keyHandle']));
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function retrieveClientData(array $data): ClientData
    {
        if (!array_key_exists('clientData', $data) || !\is_string($data['clientData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        return ClientData::create($data['clientData']);
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function extractSignatureData(array $data): array
    {
        if (!array_key_exists('signatureData', $data) || !\is_string($data['signatureData'])) {
            throw new \InvalidArgumentException('Invalid response.');
        }

        $stream = fopen('php://memory', 'r+');
        if (false === $stream) {
            throw new \InvalidArgumentException('Unable to load the registration data.');
        }
        $signatureData = Base64Url::decode($data['signatureData']);
        fwrite($stream, $signatureData);
        rewind($stream);

        $userPresenceByte = fread($stream, 1);
        if (1 !== mb_strlen($userPresenceByte, '8bit')) {
            fclose($stream);

            throw new \InvalidArgumentException('Invalid response.');
        }
        $userPresence = (bool) \ord($userPresenceByte);

        $counterBytes = fread($stream, 4);
        if (4 !== mb_strlen($counterBytes, '8bit')) {
            fclose($stream);

            throw new \InvalidArgumentException('Invalid response.');
        }
        $counter = unpack('Nctr', $counterBytes)['ctr'];
        $signature = '';
        while (!feof($stream)) {
            $signature .= fread($stream, 1024);
        }
        fclose($stream);

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
