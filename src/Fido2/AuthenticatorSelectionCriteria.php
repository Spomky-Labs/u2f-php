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

class AuthenticatorSelectionCriteria implements \JsonSerializable
{
    public const AUTHENTICATOR_ATTACHMENT_PLATFORM = 'platform';
    public const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 'cross-platform';

    public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';
    public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';
    public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    /**
     * @var string
     */
    private $authenticatorAttachment;

    /**
     * @var bool
     */
    private $requireResidentKey;

    /**
     * @var string
     */
    private $userVerification;

    /**
     * AuthenticatorSelectionCriteria constructor.
     *
     * @param string $authenticatorAttachment
     * @param bool   $requireResidentKey
     * @param string $userVerification
     */
    public function __construct(string $authenticatorAttachment, bool $requireResidentKey, string $userVerification)
    {
        $this->authenticatorAttachment = $authenticatorAttachment;
        $this->requireResidentKey = $requireResidentKey;
        $this->userVerification = $userVerification;
    }

    /**
     * @return string
     */
    public function getAuthenticatorAttachment(): string
    {
        return $this->authenticatorAttachment;
    }

    /**
     * @return bool
     */
    public function isRequireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    /**
     * @return string
     */
    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return [
            'authenticatorAttachment' => $this->authenticatorAttachment,
            'requireResidentKey'      => $this->requireResidentKey,
            'userVerification'        => $this->userVerification,
        ];
    }
}
