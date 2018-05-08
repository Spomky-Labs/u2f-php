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

class PublicKeyCredentialRequestOptions
{
    /**
     * @var string
     */
    private $challenge;

    /**
     * @var null|int
     */
    private $timeout;

    /**
     * @var string
     */
    private $rpId;

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $allowCredentials;

    /**
     * @var string
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
     * @param string                               $rpId
     * @param PublicKeyCredentialDescriptor[]      $allowCredentials
     * @param string                               $userVerification
     * @param AuthenticationExtensionsClientInputs $extensions
     */
    public function __construct(string $challenge, ?int $timeout, string $rpId, array $allowCredentials, string $userVerification, AuthenticationExtensionsClientInputs $extensions)
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
     * @return string
     */
    public function getRpId(): string
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
     * @return string
     */
    public function getUserVerification(): string
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
}
