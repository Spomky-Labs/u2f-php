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
     * @var int
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
     * @var AuthenticationExtensionsClientInputs $extensions
     */
    private $extensions;

    /**
     * PublicKeyCredentialCreationOptions constructor.
     *
     * @param PublicKeyCredentialRpEntity          $rp
     * @param PublicKeyCredentialUserEntity        $user
     * @param string                               $challenge
     * @param PublicKeyCredentialParameters[]      $pubKeyCredParams
     * @param int                                  $timeout
     * @param PublicKeyCredentialDescriptor[]      $excludeCredentials
     * @param AuthenticatorSelectionCriteria       $authenticatorSelection
     * @param string                               $attestation
     * @param AuthenticationExtensionsClientInputs $extensions
     */
    public function __construct(PublicKeyCredentialRpEntity $rp, PublicKeyCredentialUserEntity $user, string $challenge, array $pubKeyCredParams, int $timeout, array $excludeCredentials, AuthenticatorSelectionCriteria $authenticatorSelection, string $attestation, AuthenticationExtensionsClientInputs $extensions)
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
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'rp'                 => $this->rp,
            'pubKeyCredParams'   => $this->pubKeyCredParams,
            'timeout'            => $this->timeout,
            'challenge'          => $this->challenge,
            'attestation'        => $this->attestation,
            'excludeCredentials' => $this->excludeCredentials,
            'user'               => $this->user,
        ];
    }
}
