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
     * @param string                               $challenge
     * @param int|null                             $timeout
     * @param string|null                          $rpId
     * @param PublicKeyCredentialDescriptor[]      $allowCredentials
     * @param string|null                          $userVerification
     * @param AuthenticationExtensionsClientInputs $extensions
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

    /**
     * @return string
     */
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @return int|null
     */
    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    /**
     * @return string|null
     */
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

    /**
     * @return string|null
     */
    public function getUserVerification(): ?string
    {
        return $this->userVerification;
    }

    /**
     * @return AuthenticationExtensionsClientInputs
     */
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

        if (!is_null($this->timeout)) {
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
            $result[] = ord($char);
        }

        return $result;
    }
}
