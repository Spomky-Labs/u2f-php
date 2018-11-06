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

use CBOR\MapObject;
use U2FAuthentication\Fido2\AuthenticatorData;

final class FidoU2FAttestationStatementSupport implements AttestationStatementSupport
{
    private const CERTIFICATES_HASHES = [
        '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
        'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
        '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
        'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
        '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
        'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511',
    ];

    /**
     * @var string[]
     */
    private $attestationCertificates = [];

    /**
     * @param string[] $attestationCertificates
     */
    public function __construct(array $attestationCertificates = [])
    {
        $this->attestationCertificates = $attestationCertificates;
    }

    public function name(): string
    {
        return 'fido-u2f';
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        foreach (['sig', 'x5c'] as $key) {
            if (!$attestationStatement->has($key)) {
                throw new \InvalidArgumentException(\Safe\sprintf('The attestation statement value "%s" is missing.', $key));
            }
        }
        $x5c = $attestationStatement->get('x5c');
        if (!\is_array($x5c) || empty($x5c)) {
            throw new \InvalidArgumentException('The attestation statement value "x5c" must be a list with at least one certificate.');
        }

        reset($x5c);
        $x5c = $this->getPublicKeyAsPem(current($x5c));

        if (!empty($this->attestationCertificates) && true !== openssl_x509_checkpurpose($x5c, X509_PURPOSE_ANY, $this->attestationCertificates)) {
            return false;
        }

        $dataToVerify = "\0";
        $dataToVerify .= $authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataJSONHash;
        $dataToVerify .= $authenticatorData->getAttestedCredentialData()->getCredentialId();
        $dataToVerify .= $this->extractPublicKey($authenticatorData->getAttestedCredentialData()->getCredentialPublicKey());

        return 1 === openssl_verify($dataToVerify, $attestationStatement->get('sig'), $x5c, OPENSSL_ALGO_SHA256);
    }

    private function getPublicKeyAsPem(string $publicKey): string
    {
        $derCertificate = $this->unusedBytesFix($publicKey);
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

    private function extractPublicKey(?MapObject $publicKey): string
    {
        if (!$publicKey instanceof MapObject) {
            throw new \InvalidArgumentException('The public key of the attestation statement is not valid.');
        }

        $publicKey = $publicKey->getNormalizedData();
        if (!array_key_exists(-2, $publicKey) || !\is_string($publicKey[-2]) || 32 !== mb_strlen($publicKey[-2], '8bit')) {
            throw new \InvalidArgumentException('The public key of the attestation statement is not valid.');
        }
        if (!array_key_exists(-3, $publicKey) || !\is_string($publicKey[-3]) || 32 !== mb_strlen($publicKey[-3], '8bit')) {
            throw new \InvalidArgumentException('The public key of the attestation statement is not valid.');
        }

        return "\x04".$publicKey[-2].$publicKey[-3];
    }

    private function unusedBytesFix(string $derCertificate): string
    {
        $certificateHash = hash('sha256', $derCertificate);
        if (\in_array($certificateHash, self::CERTIFICATES_HASHES, true)) {
            $derCertificate[mb_strlen($derCertificate, '8bit') - 257] = "\0";
        }

        return $derCertificate;
    }
}
