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

use U2FAuthentication\Fido2\AuthenticatorData;

final class PackedAttestationStatementSupport implements AttestationStatementSupport
{
    private const CERTIFICATES_HASHES = [
        '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
        'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
        '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
        'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
        '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
        'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511',
    ];

    public function name(): string
    {
        return 'packed';
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        if (!$attestationStatement->has('sig')) {
            throw new \InvalidArgumentException('The attestation statement value "sig" is missing.');
        }

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
        if (!\is_array($certificates) || empty($certificates)) {
            throw new \InvalidArgumentException('The attestation statement value "x5c" must be a list with at least one certificate.');
        }

        //Check certificate CA chain and returns the Attestation Certificate
        $attestnCert = $this->loadFromX5C($certificates);

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
        if (!isset($parsed['version']) || 2 !== $parsed['version']) {
            throw new \InvalidArgumentException('TInvalid certificate version');
        }

        //Check subject field
        if (!isset($parsed['name']) || false === mb_strpos($parsed['name'], '/OU=Authenticator Attestation')) {
            throw new \InvalidArgumentException('Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"');
        }

        //Check extensions
        if (!isset($parsed['extensions']) || !\is_array($parsed['extensions'])) {
            throw new \InvalidArgumentException('Certificate extensions are missing');
        }

        //Check certificate is not a CA cert
        if (!isset($parsed['extensions']['basicConstraints']) || 'CA:FALSE' !== $parsed['extensions']['basicConstraints']) {
            throw new \InvalidArgumentException('The Basic Constraints extension must have the CA component set to false');
        }

        // id-fido-gen-ce-aaguid OID check
        if (\in_array('1.3.6.1.4.1.45724.1.1.4', $parsed['extensions'], true) && !hash_equals($authenticatorData->getAttestedCredentialData()->getAaguid(), $parsed['extensions']['1.3.6.1.4.1.45724.1.1.4'])) {
            throw new \InvalidArgumentException('The value of the "aaguid" does not match with the certificate');
        }
    }

    private function processWithECDAA(): bool
    {
        throw new \RuntimeException('ECDAA not supported');
    }

    private function processWithSelfAttestation(): bool
    {
        throw new \RuntimeException('Self attestation not supported');
    }

    private function getX509Certificate(string $publicKey): string
    {
        $derCertificate = $this->unusedBytesFix($publicKey);
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

    private function unusedBytesFix(string $derCertificate): string
    {
        $certificateHash = hash('sha256', $derCertificate);
        if (\in_array($certificateHash, self::CERTIFICATES_HASHES, true)) {
            $derCertificate[mb_strlen($derCertificate, '8bit') - 257] = "\0";
        }

        return $derCertificate;
    }

    private function loadFromX5C(array $x5c): string
    {
        $certificate = null;
        $last_issuer = null;
        $last_subject = null;
        foreach ($x5c as $cert) {
            $current_cert = $this->getX509Certificate($cert);
            $x509 = \Safe\openssl_x509_read($current_cert);
            if (false === $x509) {
                $last_issuer = null;
                $last_subject = null;

                break;
            }
            $parsed = \openssl_x509_parse($x509);

            \openssl_x509_free($x509);
            if (false === $parsed) {
                $last_issuer = null;
                $last_subject = null;

                break;
            }
            if (null === $last_subject) {
                $last_subject = $parsed['subject'];
                $last_issuer = $parsed['issuer'];
                $certificate = $current_cert;
            } else {
                if (\Safe\json_encode($last_issuer) === \Safe\json_encode($parsed['subject'])) {
                    $last_subject = $parsed['subject'];
                    $last_issuer = $parsed['issuer'];
                } else {
                    $last_issuer = null;
                    $last_subject = null;

                    break;
                }
            }
        }

        switch (true) {
            case null !== $certificate && 1 === \count($x5c):
                return $certificate;
            case null === $certificate:
            case \Safe\json_encode($last_issuer) !== \Safe\json_encode($last_subject):
                throw new \InvalidArgumentException('Invalid certificate chain.');
            default:
                return $certificate;
        }
    }
}
