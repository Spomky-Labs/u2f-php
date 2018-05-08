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

class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    /**
     * @var string
     */
    private $attestationObject;

    /**
     * AuthenticatorAttestationResponse constructor.
     *
     * @param string $clientDataJSON
     * @param string $attestationObject
     */
    public function __construct(string $clientDataJSON, string $attestationObject)
    {
        parent::__construct($clientDataJSON);
        $this->attestationObject = $attestationObject;
    }

    /**
     * @param array $json
     *
     * @return AuthenticatorAttestationResponse
     */
    public static function createFromJson(array $json): self
    {
        if (!array_key_exists('clientDataJSON', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('attestationObject', $json)) {
            throw new \InvalidArgumentException();
        }

        return new self(
            $json['clientDataJSON'],
            $json['attestationObject']
        );
    }

    /**
     * @return string
     */
    public function getAttestationObject(): string
    {
        return $this->attestationObject;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'clientDataJSON'    => $this->getClientDataJSON(),
            'attestationObject' => $this->attestationObject,
        ];
    }
}
