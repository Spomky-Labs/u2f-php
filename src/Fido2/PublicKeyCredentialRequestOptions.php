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

class PublicKeyCredentialRequestOptions implements \JsonSerializable
{
    public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';
    public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';
    public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';
    /**
     * @var string
     */
    private $challenge;

    /**
     * @var int|null
     */
    private $timeout;

    /**
     * @var string|null
     */
    private $rpId;

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $allowCredentials;

    /**
     * @var string|null
     */
    private $userVerification;

    /**
     * @var AuthenticationExtensionsClientInputs
     */
    private $extensions;

    /**
     * PublicKeyCredentialRequestOptions constructor.
     *
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     */
    public function __construct(string $challenge, ?int $timeout = null, ?string $rpId = null, array $allowCredentials, ?string $userVerification = null, AuthenticationExtensionsClientInputs $extensions)
    {
        $this->challenge = $challenge;
        $this->timeout = $timeout;
        $this->rpId = $rpId;
        $this->allowCredentials = $allowCredentials;
        $this->userVerification = $userVerification;
        $this->extensions = $extensions;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    public function getRpId(): ?string
    {
        return $this->rpId;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getAllowCredentials(): array
    {
        return $this->allowCredentials;
    }

    public function getUserVerification(): ?string
    {
        return $this->userVerification;
    }

    public function getExtensions(): AuthenticationExtensionsClientInputs
    {
        return $this->extensions;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        $json = [
            'rpId'      => $this->rpId,
            'challenge' => $this->splitChallenge(),
        ];

        if ($this->userVerification) {
            $json['userVerification'] = $this->userVerification;
        }

        if (!empty($this->allowCredentials)) {
            $json['allowCredentials'] = $this->allowCredentials;
        }

        if (!empty($this->extensions)) {
            $json['extensions'] = $this->extensions;
        }

        if (!\is_null($this->timeout)) {
            $json['timeout'] = $this->timeout;
        }

        return $json;
    }

    /**
     * @return int[]
     */
    private function splitChallenge(): array
    {
        $result = [];
        $split = str_split($this->challenge);
        foreach ($split as $char) {
            $result[] = \ord($char);
        }

        return $result;
    }
}
