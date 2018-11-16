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

use Base64Url\Base64Url;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\StringStream;
use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;

class PublicKeyCredentialLoader
{
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;

    private $attestationObjectLoader;
    private $decoder;

    public function __construct(AttestationObjectLoader $attestationObjectLoader, Decoder $decoder)
    {
        $this->attestationObjectLoader = $attestationObjectLoader;
        $this->decoder = $decoder;
    }

    public function load(string $data): PublicKeyCredential
    {
        $json = \Safe\json_decode($data, true);
        if (!array_key_exists('id', $json)) {
            throw new \InvalidArgumentException();
        }
        $id = Base64Url::decode($json['id']);
        if (!array_key_exists('rawId', $json)) {
            throw new \InvalidArgumentException();
        }
        $rawId = Base64Url::decode($json['rawId']);
        if (!hash_equals($id, $rawId)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('response', $json)) {
            throw new \InvalidArgumentException();
        }

        $publicKeyCredential = new PublicKeyCredential(
            $json['id'],
            $json['type'] ?? 'public-key',
            $rawId,
            $this->createResponse($json['response'])
        );

        return $publicKeyCredential;
    }

    private function createResponse(array $response): AuthenticatorResponse
    {
        if (!array_key_exists('clientDataJSON', $response)) {
            throw new \InvalidArgumentException();
        }
        if (array_key_exists('attestationObject', $response)) {
            $attestationObject = $this->attestationObjectLoader->load($response['attestationObject']);

            return new AuthenticatorAttestationResponse(
                CollectedClientData::createFormJson($response['clientDataJSON']),
                $attestationObject
            );
        }
        if (array_key_exists('authenticatorData', $response) && array_key_exists('signature', $response)) {
            $authData = Base64Url::decode($response['authenticatorData']);

            $authDataStream = new StringStream($authData);
            $rp_id_hash = $authDataStream->read(32);
            $flags = $authDataStream->read(1);
            $signCount = $authDataStream->read(4);
            $signCount = unpack('N', $signCount)[1];

            if (\ord($flags) & self::FLAG_AT) {
                $aaguid = $authDataStream->read(16);
                $credentialLength = $authDataStream->read(2);
                $credentialLength = unpack('n', $credentialLength)[1];
                $credentialId = $authDataStream->read($credentialLength);
                $credentialPublicKey = $this->decoder->decode($authDataStream);
                if (!$credentialPublicKey instanceof MapObject) {
                    throw new \InvalidArgumentException('The data does not contain a valid credential public key.');
                }
                $attestedCredentialData = new AttestedCredentialData($aaguid, $credentialId, (string) $credentialPublicKey);
            } else {
                $attestedCredentialData = null;
            }

            if (\ord($flags) & self::FLAG_ED) {
                $extension = $this->decoder->decode($authDataStream);
            } else {
                $extension = null;
            }
            $authenticatorData = new AuthenticatorData(
                $authData,
                $rp_id_hash,
                $flags,
                $signCount,
                $attestedCredentialData,
                $extension
            );

            return new AuthenticatorAssertionResponse(
                CollectedClientData::createFormJson($response['clientDataJSON']),
                $authenticatorData,
                Base64Url::decode($response['signature']),
                $response['userHandle'] ?? null
            );
        }
    }
}
