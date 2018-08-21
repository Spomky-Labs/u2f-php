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

namespace U2FAuthentication\Fido2;

use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;

class PublicKeyCredentialCreationValidator
{
    /**
     * @var AttestationStatementSupportManager
     */
    private $attestationStatementSupportManager;

    public function __construct(AttestationStatementSupportManager $attestationStatementSupportManager)
    {
        $this->attestationStatementSupportManager = $attestationStatementSupportManager;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function isValid(PublicKeyCredential $publicKeyCredential, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions): bool
    {
        if ('webauthn.create' !== $publicKeyCredential->getResponse()->getClientDataJSON()->getType()) {
            throw new \InvalidArgumentException();
        }
        if (hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $publicKeyCredential->getResponse()->getClientDataJSON()->getChallenge())) {
            throw new \InvalidArgumentException();
        }
        if ($publicKeyCredentialCreationOptions->getRp()->getId() !== $publicKeyCredential->getResponse()->getClientDataJSON()->getOrigin()) {
            throw new \InvalidArgumentException();
        }
        if ($publicKeyCredential->getResponse()->getClientDataJSON()->getTokenBinding()) {
            throw new \InvalidArgumentException();
        }
    }
}
