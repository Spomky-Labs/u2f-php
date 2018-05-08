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

class PublicKeyCredential extends Credential
{
    /**
     * @var string
     */
    private $rawId;

    /**
     * @var AuthenticatorAttestationResponse
     */
    private $response;

    /**
     * PublicKeyCredential constructor.
     *
     * @param string                           $id
     * @param string                           $type
     * @param string                           $rawId
     * @param AuthenticatorAttestationResponse $response
     */
    public function __construct(string $id, string $type, string $rawId, AuthenticatorAttestationResponse $response)
    {
        parent::__construct($id, $type);
        $this->rawId = $rawId;
        $this->response = $response;
    }

    /**
     * @param array $json
     *
     * @return PublicKeyCredential
     */
    public static function createFromJson(array $json): self
    {
        if (!array_key_exists('id', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('rawId', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('type', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('response', $json)) {
            throw new \InvalidArgumentException();
        }

        return new self(
            $json['id'],
            $json['type'],
            $json['rawId'],
            AuthenticatorAttestationResponse::createFromJson($json['response'])
        );
    }

    /**
     * @param string $data
     *
     * @return PublicKeyCredential
     */
    public static function createFromReceivedData(string $data): self
    {
        $json = json_decode($data, true);

        return self::createFromJson($json);
    }

    /**
     * @return string
     */
    public function getRawId(): string
    {
        return $this->rawId;
    }

    /**
     * @return AuthenticatorAttestationResponse
     */
    public function getResponse(): AuthenticatorAttestationResponse
    {
        return $this->response;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'id'       => $this->getId(),
            'type'     => $this->getType(),
            'rawId'    => $this->getRawId(),
            'response' => $this->response,
        ];
    }
}
