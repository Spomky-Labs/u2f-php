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
     * @var null|string
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
     * @param null|string $authenticatorAttachment
     * @param bool   $requireResidentKey
     * @param string $userVerification
     */
    public function __construct(?string $authenticatorAttachment = null, bool $requireResidentKey = false, string $userVerification = self::USER_VERIFICATION_REQUIREMENT_PREFERRED)
    {
        $this->authenticatorAttachment = $authenticatorAttachment;
        $this->requireResidentKey = $requireResidentKey;
        $this->userVerification = $userVerification;
    }

    /**
     * @return null|string
     */
    public function getAuthenticatorAttachment(): ?string
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
        $json = [
            'requireResidentKey'      => $this->requireResidentKey,
            'userVerification'        => $this->userVerification,
        ];
        if ($this->authenticatorAttachment) {
            $json['authenticatorAttachment'] = $this->authenticatorAttachment;
        }

        return $json;
    }
}
