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

class AuthenticatorAssertionResponseValidator
{
    private $credentialRepository;

    public function __construct(CredentialRepository $credentialRepository)
    {
        $this->credentialRepository = $credentialRepository;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(string $credentialId, AuthenticatorAssertionResponse $authenticatorAssertionResponse, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ?string $rpId = null): void
    {
        /* @see 7.2.1 */
        if (!$this->isCredentialIdAllowed($credentialId, $publicKeyCredentialRequestOptions->getAllowCredentials())) {
            throw new \InvalidArgumentException('The credential ID is not allowed.');
        }
        /* @see 7.2.2 */
        if (null !== $authenticatorAssertionResponse->getUserHandle()) {
            throw new \RuntimeException('Not supported.'); //TODO: implementation shall be done.
        }

        /* @see 7.2.3 */
        if (!$this->credentialRepository->hasCredentialPublicKey($credentialId)) {
            throw new \InvalidArgumentException('No credential public key available for the given credential ID.');
        }
        $credentialPublicKey = $this->credentialRepository->getCredentialPublicKey($credentialId);

        /** @see 7.2.4 */
        /** @see 7.2.5 */
        //Nothirg to do. Use of objets directly

        /** @see 7.2.6 */
        $C = $authenticatorAssertionResponse->getClientDataJSON();

        /* @see 7.2.7 */
        if ('webauthn.get' !== $C->getType()) {
            throw new \InvalidArgumentException('The client data type is not "webauthn.get".');
        }

        /* @see 7.2.8 */
        if (hash_equals($publicKeyCredentialRequestOptions->getChallenge(), $C->getChallenge())) {
            throw new \InvalidArgumentException('Invalid challenge.');
        }

        /** @see 7.2.9 */
        $rpId = $rpId ?? $publicKeyCredentialRequestOptions->getRpId();
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

        /* @see 7.2.10 */
        if ($C->getTokenBinding()) {
            throw new \InvalidArgumentException('Token binding not supported.');
        }

        /** @see 7.2.11 */
        $rpIdHash = hash('sha256', $rpId);
        if (hash_equals($rpIdHash, $authenticatorAssertionResponse->getAuthenticatorData()->getRpIdHash())) {
            throw new \InvalidArgumentException('rpId hash mismatch.');
        }

        /* @see 7.2.12 */
        if (!$authenticatorAssertionResponse->getAuthenticatorData()->isUserPresent()) {
            throw new \InvalidArgumentException('User was not present');
        }

        /* @see 7.2.13 */
        if (AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialRequestOptions->getUserVerification() && !$authenticatorAssertionResponse->getAuthenticatorData()->isUserVerified()) {
            throw new \InvalidArgumentException('User authentication required.');
        }

        /* @see 7.2.14 */
        if (0 !== $publicKeyCredentialRequestOptions->getExtensions()->count()) {
            throw new \InvalidArgumentException('Extensions not supported.');
        }

        /** @see 7.2.15 */
        $getClientDataJSONHash = hash('sha256', $authenticatorAssertionResponse->getClientDataJSON()->getRawData());

        /* @see 7.2.16 */
        //TODO: check signature

        /* @see 7.2.17 */
        //TODO: check counter

        /* @see 7.2.18 */
        //Great!
    }

    private function isCredentialIdAllowed(string $credentialId, array $allowedCredentials): bool
    {
        foreach ($allowedCredentials as $allowedCredential) {
            if (hash_equals($allowedCredential->getId(), $credentialId)) {
                return true;
            }
        }

        return false;
    }
}
