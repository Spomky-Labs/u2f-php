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
        if (!$this->credentialRepository->hasCredential($credentialId)) {
            throw new \InvalidArgumentException('No credential public key available for the given credential ID.');
        }
        $credentialPublicKey = $this->credentialRepository->getCredentialPublicKey($credentialId);

        /** @see 7.2.4 */
        /** @see 7.2.5 */
        //Nothing to do. Use of objets directly

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
        $rpIdHash = hash('sha256', $rpId, true);
        if (!hash_equals($rpIdHash, $authenticatorAssertionResponse->getAuthenticatorData()->getRpIdHash())) {
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
        $getClientDataJSONHash = hash('sha256', $authenticatorAssertionResponse->getClientDataJSON()->getRawData(), true);

        /* @see 7.2.16 */
        $coseKey = $credentialPublicKey->getNormalizedData();
        $key = "\04".$coseKey[-2].$coseKey[-3];
        if (1 !== openssl_verify($authenticatorAssertionResponse->getAuthenticatorData()->getAuthData().$getClientDataJSONHash, $authenticatorAssertionResponse->getSignature(), $this->getPublicKeyAsPem($key), OPENSSL_ALGO_SHA256)) {
            throw new \InvalidArgumentException('Invalid signature.');
        }

        /* @see 7.2.17 */
        $storedCounter = $this->credentialRepository->getCredentialCounter($credentialId);
        $currentCounter = $authenticatorAssertionResponse->getAuthenticatorData()->getSignCount();
        if ($storedCounter >= $currentCounter) {
            throw new \InvalidArgumentException('Invalid counter.');
        }
        $this->credentialRepository->updateCredentialCounter($credentialId, $currentCounter);

        /* @see 7.2.18 */
        //Great!
    }

    private function getPublicKeyAsPem(string $key): string
    {
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\0".$key;

        $pem = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $pem;
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
