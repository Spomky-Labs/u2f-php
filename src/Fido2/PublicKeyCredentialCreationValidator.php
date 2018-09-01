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
    public function check(PublicKeyCredential $publicKeyCredential, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ?string $rpId = null): void
    {
        /** @see 7.1.2 */
        $C = $publicKeyCredential->getResponse()->getClientDataJSON();

        /** @see 7.1.3 */
        if ('webauthn.create' !== $C->getType()) {
            throw new \InvalidArgumentException('The client data type is not "webauthn.create".');
        }

        /** @see 7.1.4 */
        if (hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge())) {
            throw new \InvalidArgumentException('Invalid challenge.');
        }

        /** @see 7.1.5 */
        if ($rpId === null && $publicKeyCredentialCreationOptions->getRp()->getId() === null) {
            throw new \InvalidArgumentException('No rpId.');
        }
        $rpId = $rpId ?? $publicKeyCredentialCreationOptions->getRp()->getId();
        if ($C->getOrigin() !== $rpId) {
            throw new \InvalidArgumentException('rpId mismatch.');
        }

        /** @see 7.1.6 */
        if ($C->getTokenBinding()) {
            throw new \InvalidArgumentException('Token binding not supported.');
        }

        /** @see 7.1.7 */
        $getClientDataJSONHash = hash('sha256', $publicKeyCredential->getResponse()->getClientDataJSON()->getRawData());

        /** @see 7.1.8 */
        $attestationObject = $publicKeyCredential->getResponse()->getAttestationObject();

        /** @see 7.1.9 */
        $rpIdHash = hash('sha256', $rpId);
        if (hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash())) {
            throw new \InvalidArgumentException('rpId hash mismatch.');
        }

        /** @see 7.1.10 */
        if (!$attestationObject->getAuthData()->isUserPresent()) {
            throw new \InvalidArgumentException('User was not present');
        }

        /** @see 7.1.11 */
        if ($publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED && !$attestationObject->getAuthData()->isUserVerified()) {
            throw new \InvalidArgumentException('User authentication required.');
        }

        /** @see 7.1.12 */
        if ($publicKeyCredentialCreationOptions->getExtensions()->count() !== 0) {
            throw new \InvalidArgumentException('Extensions not supported.');
        }

        /** @see 7.1.13 */
        $fmt = $attestationObject->getAttStmt()->getFmt();
        if (!$this->attestationStatementSupportManager->has($fmt)) {
            throw new \InvalidArgumentException('Unsuppoorted attestation statement format.');
        }

        /** @see 7.1.14 */
        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        if (!$attestationStatementSupport->isValid($attestationObject->getAttStmt(), $attestationObject->getAuthData(), $C)) {
            throw new \InvalidArgumentException('Unvalid attestation statement.');
        }

        /** @see 7.1.15 */
        /** @see 7.1.16 */
        /** @see 7.1.17 */
        $credentialId = $attestationObject->getAuthData()->getAttestedCredentialData()->getCredentialId();
        if ($this->credentialIdRepository->hasCredentialId($credentialId)) {
            throw new \InvalidArgumentException('No credential ID.');
        }

        /** @see 7.1.18 */
        /** @see 7.1.19 */
    }
}
