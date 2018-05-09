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

class PublicKeyCredentialCreationOptions implements \JsonSerializable
{
    public const ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 'none';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 'indirect';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 'direct';

    /**
     * @var PublicKeyCredentialRpEntity
     */
    private $rp;

    /**
     * @var PublicKeyCredentialUserEntity
     */
    private $user;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var PublicKeyCredentialParameters[]
     */
    private $pubKeyCredParams;

    /**
     * @var int|null
     */
    private $timeout;

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $excludeCredentials;

    /**
     * @var AuthenticatorSelectionCriteria
     */
    private $authenticatorSelection;

    /**
     * @var string
     */
    private $attestation;

    /**
     * @var AuthenticationExtensionsClientInputs
     */
    private $extensions;

    /**
     * PublicKeyCredentialCreationOptions constructor.
     *
     * @param PublicKeyCredentialRpEntity          $rp
     * @param PublicKeyCredentialUserEntity        $user
     * @param string                               $challenge
     * @param PublicKeyCredentialParameters[]      $pubKeyCredParams
     * @param null|int                             $timeout
     * @param PublicKeyCredentialDescriptor[]      $excludeCredentials
     * @param AuthenticatorSelectionCriteria       $authenticatorSelection
     * @param string                               $attestation
     * @param AuthenticationExtensionsClientInputs $extensions
     */
    public function __construct(PublicKeyCredentialRpEntity $rp, PublicKeyCredentialUserEntity $user, string $challenge, array $pubKeyCredParams, ?int $timeout, array $excludeCredentials, AuthenticatorSelectionCriteria $authenticatorSelection, string $attestation = self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE, AuthenticationExtensionsClientInputs $extensions)
    {
        $this->rp = $rp;
        $this->user = $user;
        $this->challenge = $challenge;
        $this->pubKeyCredParams = $pubKeyCredParams;
        $this->timeout = $timeout;
        $this->excludeCredentials = $excludeCredentials;
        $this->authenticatorSelection = $authenticatorSelection;
        $this->attestation = $attestation;
        $this->extensions = $extensions;
    }

    /**
     * @return PublicKeyCredentialRpEntity
     */
    public function getRp(): PublicKeyCredentialRpEntity
    {
        return $this->rp;
    }

    /**
     * @return PublicKeyCredentialUserEntity
     */
    public function getUser(): PublicKeyCredentialUserEntity
    {
        return $this->user;
    }

    /**
     * @return string
     */
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    public function getPubKeyCredParams(): array
    {
        return $this->pubKeyCredParams;
    }

    /**
     * @return null|int
     */
    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getExcludeCredentials(): array
    {
        return $this->excludeCredentials;
    }

    /**
     * @return AuthenticatorSelectionCriteria
     */
    public function getAuthenticatorSelection(): AuthenticatorSelectionCriteria
    {
        return $this->authenticatorSelection;
    }

    /**
     * @return string
     */
    public function getAttestation(): string
    {
        return $this->attestation;
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
            'rp'                     => $this->rp,
            'pubKeyCredParams'       => $this->pubKeyCredParams,
            'challenge'              => $this->splitChallenge(),
            'attestation'            => $this->attestation,
            'user'                   => $this->user,
            'authenticatorSelection' => $this->authenticatorSelection,
        ];

        if (!empty($this->excludeCredentials)) {
            $json['excludeCredentials'] = $this->excludeCredentials;
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
