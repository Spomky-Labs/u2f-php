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
    private $attestationStatementSupportManager;
    private $credentialIdRepository;

    public function __construct(AttestationStatementSupportManager $attestationStatementSupportManager, CredentialIdRepository $credentialIdRepository)
    {
        $this->attestationStatementSupportManager = $attestationStatementSupportManager;
        $this->credentialIdRepository = $credentialIdRepository;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function isValid(PublicKeyCredential $publicKeyCredential, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ?string $rpId = null): bool
    {
        /** @see 7.1.2 */
        $C = $publicKeyCredential->getResponse()->getClientDataJSON();

        /** @see 7.1.3 */
        if ('webauthn.create' !== $C->getType()) {
            return false;
        }

        /** @see 7.1.4 */
        if (hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge())) {
            return false;
        }

        /** @see 7.1.5 */
        if ($rpId === null && $publicKeyCredentialCreationOptions->getRp()->getId() === null) {
            return false;
        }
        $rpId = $rpId ?? $publicKeyCredentialCreationOptions->getRp()->getId();
        if ($C->getOrigin() !== $rpId) {
            return false;
        }

        /** @see 7.1.6 */
        if ($C->getTokenBinding()) {
            throw new \InvalidArgumentException('Not supported');
        }

        /** @see 7.1.7 */
        $getClientDataJSONHash = hash('sha256', $publicKeyCredential->getResponse()->getClientDataJSON()->getRawData());

        /** @see 7.1.8 */
        $attestationObject = $publicKeyCredential->getResponse()->getAttestationObject();

        /** @see 7.1.9 */
        $rpIdHash = hash('sha256', $rpId);
        if (hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash())) {
            return false;
        }

        /** @see 7.1.10 */
        if (!$attestationObject->getAuthData()->isUserPresent()) {
            return false;
        }

        /** @see 7.1.11 */
        if ($publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED && !$attestationObject->getAuthData()->isUserVerified()) {
            return false;
        }

        /** @see 7.1.12 */
        if ($publicKeyCredentialCreationOptions->getExtensions()->count() !== 0) {
            return false;
        }

        /** @see 7.1.13 */
        $fmt = $attestationObject->getAttStmt()->getFmt();
        if (!$this->attestationStatementSupportManager->has($fmt)) {
            return false;
        }

        /** @see 7.1.14 */
        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        if (!$attestationStatementSupport->isValid($attestationObject->getAttStmt(), $attestationObject->getAuthData(), $C)) {
            return false;
        }

        /** @see 7.1.15 */
        /** @see 7.1.16 */
        /** @see 7.1.17 */
        $credentialId = $attestationObject->getAuthData()->getAttestedCredentialData()->getCredentialId();
        if ($this->credentialIdRepository->hasCredentialId($credentialId)) {
            return false;
        }

        /** @see 7.1.18 */
        /** @see 7.1.19 */

        return true;
    }
}
