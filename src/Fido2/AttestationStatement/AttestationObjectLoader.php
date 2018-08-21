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

namespace U2FAuthentication\Fido2\AttestationStatement;

use Base64Url\Base64Url;
use CBOR\Decoder;
use U2FAuthentication\Fido2\AttestedCredentialData;
use U2FAuthentication\Fido2\AuthenticatorData;
use U2FAuthentication\Fido2\StringStream;

class AttestationObjectLoader
{
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;

    /**
     * @var Decoder
     */
    private $decoder;

    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    public function load(string $data): AttestationObject
    {
        $decodedData = Base64Url::decode($data);
        $stream = new StringStream($decodedData);
        $attestationObject = $this->decoder->decode($stream)->getNormalizedData();
        $authData = $attestationObject['authData'];

        $authDataStream = new StringStream($authData);
        $rp_id_hash = $authDataStream->read(32);
        $flags = $authDataStream->read(1);
        $signCount = $authDataStream->read(4);
        $signCount = unpack('l', $signCount)[1];

        if (\ord($flags) & self::FLAG_AT) {
            $aaguid = $authDataStream->read(16);
            $credentialLength = $authDataStream->read(2);
            $credentialLength = unpack('n', $credentialLength)[1];
            $credentialId = $authDataStream->read($credentialLength);
            $credentialPublicKey = $this->decoder->decode($authDataStream);
            //TODO: should be converted into a COSE Key
            $attestedCredentialData = new AttestedCredentialData($aaguid, $credentialId, $credentialPublicKey->getNormalizedData());
        } else {
            $attestedCredentialData = null;
        }

        if (\ord($flags) & self::FLAG_ED) {
            //TODO: should be correctly handled
            $extension = $this->decoder->decode($authDataStream);
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

        return new AttestationObject(
            $data,
            new AttestationStatement($attestationObject['fmt'], $attestationObject['attStmt']),
            $authenticatorData
        );
    }
}
