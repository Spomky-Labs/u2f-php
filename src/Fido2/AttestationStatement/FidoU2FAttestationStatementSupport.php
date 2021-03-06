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
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\StringStream;
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

    private $decoder;

    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    public function name(): string
    {
        return 'fido-u2f';
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        foreach (['sig', 'x5c'] as $key) {
            Assertion::true($attestationStatement->has($key), \Safe\sprintf('The attestation statement value "%s" is missing.', $key));
        }
        $certificates = $attestationStatement->get('x5c');
        Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with one certificate.');
        Assertion::count($certificates, 1, 'The attestation statement value "x5c" must be a list with one certificate.');

        reset($certificates);
        $certificate = $this->getCertificateAsPem(current($certificates));

        $dataToVerify = "\0";
        $dataToVerify .= $authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataJSONHash;
        $dataToVerify .= $authenticatorData->getAttestedCredentialData()->getCredentialId();
        $dataToVerify .= $this->extractPublicKey($authenticatorData->getAttestedCredentialData()->getCredentialPublicKey());

        return 1 === openssl_verify($dataToVerify, $attestationStatement->get('sig'), $certificate, OPENSSL_ALGO_SHA256);
    }

    private function getCertificateAsPem(string $publicKey): string
    {
        $derCertificate = $this->unusedBytesFix($publicKey);

        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

    private function extractPublicKey(?string $publicKey): string
    {
        Assertion::notNull($publicKey, 'The attestated credential data does not contain a valid public key.');

        $publicKey = $this->decoder->decode(new StringStream($publicKey));
        Assertion::isInstanceOf($publicKey, MapObject::class, 'The attestated credential data does not contain a valid public key.');

        $publicKey = $publicKey->getNormalizedData();
        Assertion::false(!array_key_exists(-2, $publicKey) || !\is_string($publicKey[-2]) || 32 !== mb_strlen($publicKey[-2], '8bit'), 'The public key of the attestation statement is not valid.');
        Assertion::false(!array_key_exists(-3, $publicKey) || !\is_string($publicKey[-3]) || 32 !== mb_strlen($publicKey[-3], '8bit'), 'The public key of the attestation statement is not valid.');

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
