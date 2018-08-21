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
use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;

class PublicKeyCredentialLoader
{
    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var AttestationObjectLoader
     */
    private $attestationObjectLoader;

    public function __construct(Decoder $decoder, AttestationObjectLoader $attestationObjectLoader)
    {
        $this->decoder = $decoder;
        $this->attestationObjectLoader = $attestationObjectLoader;
    }

    public function load(string $data): PublicKeyCredential
    {
        $json = json_decode($data, true);
        if (!array_key_exists('id', $json)) {
            throw new \InvalidArgumentException();
        }
        $id = Base64Url::decode($json['id']);
        if (!array_key_exists('rawId', $json)) {
            throw new \InvalidArgumentException();
        }
        $rawId = Base64Url::decode($json['rawId']);
        if (!array_key_exists('type', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!hash_equals($id, $rawId)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('response', $json)) {
            throw new \InvalidArgumentException();
        }

        $publicKeyCredential = new PublicKeyCredential(
            $json['id'],
            $json['type'],
            $rawId,
            $this->createAuthenticatorResponse($json['response'])
        );

        return $publicKeyCredential;
    }

    private function createAuthenticatorResponse(array $response): AuthenticatorAttestationResponse
    {
        if (!array_key_exists('clientDataJSON', $response)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('attestationObject', $response)) {
            throw new \InvalidArgumentException();
        }
        $attestationObject = $this->attestationObjectLoader->load($response['attestationObject']);

        return new AuthenticatorAttestationResponse(
            CollectedClientData::createFormJson($response['clientDataJSON']),
            $attestationObject
        );
    }
}
