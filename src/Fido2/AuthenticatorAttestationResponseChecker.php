<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace U2FAuthentication\Fido2;

use Base64Url\Base64Url;
use CBOR\Decoder;

class AuthenticatorAttestationResponseChecker
{
    private const CERTIFICATES_HASHES = [
        '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
        'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
        '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
        'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
        '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
        'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511',
    ];
    private const FLAG_AT   = 0b01000000;
    private const FLAG_ED   = 0b10000000;

    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * AttestationObjectParser constructor.
     *
     * @param Decoder $decoder
     */
    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    /**
     * @param PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions
     * @param AuthenticatorAttestationResponse   $authenticatorAttestationResponse
     */
    public function check(PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, AuthenticatorAttestationResponse $authenticatorAttestationResponse)
    {
        $this->checkClientData($publicKeyCredentialCreationOptions, $authenticatorAttestationResponse->getClientDataJSON());
    }

    private function checkClientData(PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, string $clientData): void
    {
        $decoded = Base64Url::decode($clientData);
        $json = json_decode($decoded, true);

        if (!hash_equals($publicKeyCredentialCreationOptions->getChallenge(), Base64Url::decode($json['challenge']))) {
            throw new \InvalidArgumentException();
        }
        if ($publicKeyCredentialCreationOptions->getRp()->getId()) {

        }
    }


    /**
     * @param string $attestationObject
     *
     * @return AuthenticatorData
     */
    public function loadAttestationObject(string $attestationObject): AuthenticatorData
    {
        $decodedAttestationObject = Base64Url::decode($attestationObject);
        $stream = new StringStream($decodedAttestationObject);
        $data = $this->decoder->decode($stream);

        dump($data);
        $normalized = $data->getNormalizedData();
        foreach ($normalized['attStmt']['x5c'] as $cert) {
            dump($this->getPublicKeyAsPem($cert));

        }
        dump(base64_encode($normalized['attStmt']['sig']));
        $authDataStream = new StringStream($normalized['authData']);

        $rp_id_hash = $authDataStream->read(32);
        $flags = $authDataStream->read(1);
        $signCount = $authDataStream->read(4);
        $signCount = unpack('l', $signCount)[1];

        if (ord($flags) & self::FLAG_AT) {
            $aaguid = $authDataStream->read(16);
            $credentialLength = $authDataStream->read(2);
            $credentialLength = unpack('n', $credentialLength)[1];
            $credentialId = $authDataStream->read($credentialLength);
            $credentialPublicKey = $this->decoder->decode($authDataStream);
            //TODO: should be converted into a COSE Key
            $attestedCredentialData  = new AttestedCredentialData($aaguid, $credentialId, $credentialPublicKey);
        } else {
            $attestedCredentialData = null;
        }

        if (ord($flags) & self::FLAG_ED) {
            $extension = $this->decoder->decode($authDataStream);
            //TODO: should be correctly handled
        } else {
            $extension = null;
        }
        $authenticatorData = new AuthenticatorData(
            $rp_id_hash,
            $flags,
            $signCount,
            $attestedCredentialData,
            $extension
        );

        return $authenticatorData;
    }

    /**
     * @param string $publicKey
     *
     * @return string
     */
    private function getPublicKeyAsPem(string $publicKey): string
    {

        $derCertificate = $this->unusedBytesFix($publicKey);
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

    /**
     * @param string $derCertificate
     *
     * @return string
     */
    private function unusedBytesFix(string $derCertificate): string
    {
        $certificateHash = hash('sha256', $derCertificate);
        if (in_array($certificateHash, self::CERTIFICATES_HASHES)) {
            $derCertificate[mb_strlen($derCertificate, '8bit') - 257] = "\0";
        }

        return $derCertificate;
    }
}
