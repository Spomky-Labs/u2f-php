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

class AuthenticatorAttestationResponseValidator
{
    private $attestationStatementSupportManager;
    private $credentialRepository;

    public function __construct(AttestationStatementSupportManager $attestationStatementSupportManager, CredentialRepository $credentialRepository)
    {
        $this->attestationStatementSupportManager = $attestationStatementSupportManager;
        $this->credentialRepository = $credentialRepository;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ?string $rpId = null): void
    {
        /** @see 7.1.1 */
        //Nothing to do

        /** @see 7.1.2 */
        $C = $authenticatorAttestationResponse->getClientDataJSON();

        /* @see 7.1.3 */
        if ('webauthn.create' !== $C->getType()) {
            throw new \InvalidArgumentException('The client data type is not "webauthn.create".');
        }

        /* @see 7.1.4 */
        if (!hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge())) {
            throw new \InvalidArgumentException('Invalid challenge.');
        }

        /** @see 7.1.5 */
        $rpId = $rpId ?? $publicKeyCredentialCreationOptions->getRp()->getId();
        if (null === $rpId) {
            throw new \InvalidArgumentException('No rpId.');
        }
        $parsedRelyingPartyId = parse_url($C->getOrigin());
        if (!array_key_exists('host', $parsedRelyingPartyId) || !\is_string($parsedRelyingPartyId['host'])) {
            throw new \InvalidArgumentException('Invalid origin rpId.');
        }
        if ($parsedRelyingPartyId['host'] !== $rpId) {
            throw new \InvalidArgumentException('rpId mismatch.');
        }

        /* @see 7.1.6 */
        if ($C->getTokenBinding()) {
            throw new \InvalidArgumentException('Token binding not supported.');
        }

        /** @see 7.1.7 */
        $getClientDataJSONHash = hash('sha256', $authenticatorAttestationResponse->getClientDataJSON()->getRawData(), true);

        /** @see 7.1.8 */
        $attestationObject = $authenticatorAttestationResponse->getAttestationObject();

        /** @see 7.1.9 */
        $rpIdHash = hash('sha256', $rpId, true);
        if (!hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash())) {
            throw new \InvalidArgumentException('rpId hash mismatch.');
        }

        /* @see 7.1.10 */
        if (!$attestationObject->getAuthData()->isUserPresent()) {
            throw new \InvalidArgumentException('User was not present');
        }

        /* @see 7.1.11 */
        if (AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification() && !$attestationObject->getAuthData()->isUserVerified()) {
            throw new \InvalidArgumentException('User authentication required.');
        }

        /* @see 7.1.12 */
        if (0 !== $publicKeyCredentialCreationOptions->getExtensions()->count()) {
            throw new \InvalidArgumentException('Extensions not supported.');
        }

        /** @see 7.1.13 */
        $fmt = $attestationObject->getAttStmt()->getFmt();
        if (!$this->attestationStatementSupportManager->has($fmt)) {
            throw new \InvalidArgumentException('Unsuppoorted attestation statement format.');
        }

        /** @see 7.1.14 */
        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        if (!$attestationStatementSupport->isValid($getClientDataJSONHash, $attestationObject->getAttStmt(), $attestationObject->getAuthData(), $C)) {
            throw new \InvalidArgumentException('Unvalid attestation statement.');
        }

        /** @see 7.1.15 */
        /** @see 7.1.16 */
        /** @see 7.1.17 */
        $credentialId = $attestationObject->getAuthData()->getAttestedCredentialData()->getCredentialId();
        if ($this->credentialRepository->hasCredential($credentialId)) {
            throw new \InvalidArgumentException('The credential ID already exists.');
        }

        /* @see 7.1.18 */
        /* @see 7.1.19 */
    }
}
