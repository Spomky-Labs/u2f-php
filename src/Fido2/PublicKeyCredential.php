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
     * @var AuthenticatorResponse
     */
    private $response;

    /**
     * PublicKeyCredential constructor.
     *
     * @param string                $id
     * @param string                $type
     * @param string                $rawId
     * @param AuthenticatorResponse $response
     */
    public function __construct(string $id, string $type, string $rawId, AuthenticatorResponse $response)
    {
        parent::__construct($id, $type);
        $this->rawId = $rawId;
        $this->response = $response;
    }

    /**
     * @return string
     */
    public function getRawId(): string
    {
        return $this->rawId;
    }

    /**
     * @return AuthenticatorResponse
     */
    public function getResponse(): AuthenticatorResponse
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
