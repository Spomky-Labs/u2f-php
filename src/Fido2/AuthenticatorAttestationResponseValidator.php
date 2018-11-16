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

use Assert\Assertion;
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
        Assertion::eq('webauthn.create', $C->getType(), 'The client data type is not "webauthn.create".');

        /* @see 7.1.4 */
        Assertion::true(hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge()), 'Invalid challenge.');

        /** @see 7.1.5 */
        $rpId = $rpId ?? $publicKeyCredentialCreationOptions->getRp()->getId();
        Assertion::notNull($rpId, 'No rpId.');

        $parsedRelyingPartyId = parse_url($C->getOrigin());
        Assertion::true(array_key_exists('host', $parsedRelyingPartyId) && \is_string($parsedRelyingPartyId['host']), 'Invalid origin rpId.');

        Assertion::false(null !== $rpId && $parsedRelyingPartyId['host'] !== $rpId, 'rpId mismatch.');

        /* @see 7.1.6 */
        Assertion::null($C->getTokenBinding(), 'Token binding not supported.');

        /** @see 7.1.7 */
        $getClientDataJSONHash = hash('sha256', $authenticatorAttestationResponse->getClientDataJSON()->getRawData(), true);

        /** @see 7.1.8 */
        $attestationObject = $authenticatorAttestationResponse->getAttestationObject();

        /** @see 7.1.9 */
        $rpIdHash = hash('sha256', $rpId, true);
        Assertion::true(hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash()), 'rpId hash mismatch.');

        /* @see 7.1.10 */
        Assertion::true($attestationObject->getAuthData()->isUserPresent(), 'User was not present');

        /* @see 7.1.11 */
        Assertion::false(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification() && !$attestationObject->getAuthData()->isUserVerified(), 'User authentication required.');

        /* @see 7.1.12 */
        Assertion::null($attestationObject->getAuthData()->getExtensions(), 'Extensions not supported.');

        /** @see 7.1.13 */
        $fmt = $attestationObject->getAttStmt()->getFmt();
        Assertion::true($this->attestationStatementSupportManager->has($fmt), 'Unsuppoorted attestation statement format.');

        /** @see 7.1.14 */
        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        Assertion::true($attestationStatementSupport->isValid($getClientDataJSONHash, $attestationObject->getAttStmt(), $attestationObject->getAuthData()), 'Invalid attestation statement.');

        /** @see 7.1.15 */
        /** @see 7.1.16 */
        /** @see 7.1.17 */
        $credentialId = $attestationObject->getAuthData()->getAttestedCredentialData()->getCredentialId();
        Assertion::false($this->credentialRepository->has($credentialId), 'The credential ID already exists.');

        /* @see 7.1.18 */
        /* @see 7.1.19 */
    }
}
