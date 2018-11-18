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

namespace U2FAuthentication\Fido2\AttestationStatement;

use Assert\Assertion;
use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\CertificateChainChecker;

final class PackedAttestationStatementSupport implements AttestationStatementSupport
{
    public function name(): string
    {
        return 'packed';
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        Assertion::true($attestationStatement->has('sig'), 'The attestation statement value "sig" is missing.');

        switch (true) {
            case $attestationStatement->has('x5c'):
                return $this->processWithCertificate($clientDataJSONHash, $attestationStatement, $authenticatorData);
            case $attestationStatement->has('ecdaaKeyId'):
                return $this->processWithECDAA();
            default:
                return $this->processWithSelfAttestation();
        }
    }

    private function processWithCertificate(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        $certificates = $attestationStatement->get('x5c');
        Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with at least one certificate.');

        //Check certificate CA chain and returns the Attestation Certificate
        $attestnCert = CertificateChainChecker::check($certificates);

        $signedData = $authenticatorData->getAuthData().$clientDataJSONHash;
        $result = openssl_verify($signedData, $attestationStatement->get('sig'), $attestnCert, OPENSSL_ALGO_SHA256);
        if (1 !== $result) {
            return false;
        }

        $this->checkCertificate($attestnCert, $authenticatorData);

        return true;
    }

    private function checkCertificate(string $attestnCert, AuthenticatorData $authenticatorData): void
    {
        $parsed = openssl_x509_parse($attestnCert);

        //Check version
        Assertion::false(!isset($parsed['version']) || 2 !== $parsed['version'], 'Invalid certificate version');

        //Check subject field
        Assertion::false(!isset($parsed['name']) || false === mb_strpos($parsed['name'], '/OU=Authenticator Attestation'), 'Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"');

        //Check extensions
        Assertion::false(!isset($parsed['extensions']) || !\is_array($parsed['extensions']), 'Certificate extensions are missing');

        //Check certificate is not a CA cert
        Assertion::false(!isset($parsed['extensions']['basicConstraints']) || 'CA:FALSE' !== $parsed['extensions']['basicConstraints'], 'The Basic Constraints extension must have the CA component set to false');

        // id-fido-gen-ce-aaguid OID check
        Assertion::false(\in_array('1.3.6.1.4.1.45724.1.1.4', $parsed['extensions'], true) && !hash_equals($authenticatorData->getAttestedCredentialData()->getAaguid(), $parsed['extensions']['1.3.6.1.4.1.45724.1.1.4']), 'The value of the "aaguid" does not match with the certificate');
    }

    private function processWithECDAA(): bool
    {
        throw new \RuntimeException('ECDAA not supported');
    }

    private function processWithSelfAttestation(): bool
    {
        throw new \RuntimeException('Self attestation not supported');
    }
}
