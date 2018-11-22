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

namespace U2FAuthentication\Tests\Functional\Fido2;

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use PHPUnit\Framework\TestCase;
use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;
use U2FAuthentication\Fido2\AttestationStatement\FidoU2FAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\NoneAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\PackedAttestationStatementSupport;
use U2FAuthentication\Fido2\AuthenticatorAssertionResponseValidator;
use U2FAuthentication\Fido2\AuthenticatorAttestationResponseValidator;
use U2FAuthentication\Fido2\CredentialRepository;
use U2FAuthentication\Fido2\PublicKeyCredentialLoader;

/**
 * @group functional
 * @group Fido2
 */
abstract class Fido2TestCase extends TestCase
{
    /**
     * @var null|PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    protected function getPublicKeyCredentialLoader(): PublicKeyCredentialLoader
    {
        if (!$this->publicKeyCredentialLoader) {
            $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader(
                $this->getAttestationObjectLoader(),
                $this->getDecoder()
            );
        }

        return $this->publicKeyCredentialLoader;
    }

    /**
     * @var null|AuthenticatorAttestationResponseValidator
     */
    private $authenticatorAttestationResponseValidator;

    protected function getAuthenticatorAttestationResponseValidator(CredentialRepository $credentialRepository): AuthenticatorAttestationResponseValidator
    {
        if (!$this->authenticatorAttestationResponseValidator) {
            $this->authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
                $this->getAttestationStatementSupportManager(),
                $credentialRepository
            );
        }

        return $this->authenticatorAttestationResponseValidator;
    }

    /**
     * @var null|AuthenticatorAssertionResponseValidator
     */
    private $authenticatorAssertionResponseValidator;

    protected function getAuthenticatorAssertionResponseValidator(CredentialRepository $credentialRepository): AuthenticatorAssertionResponseValidator
    {
        if (!$this->authenticatorAssertionResponseValidator) {
            $this->authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
                $credentialRepository,
                $this->getDecoder()
            );
        }

        return $this->authenticatorAssertionResponseValidator;
    }

    /**
     * @var null|Decoder
     */
    private $decoder;

    private function getDecoder(): Decoder
    {
        if (!$this->decoder) {
            $this->decoder = new Decoder(
                new TagObjectManager(),
                new OtherObjectManager()
            );
        }

        return $this->decoder;
    }

    /**
     * @var null|AttestationStatementSupportManager
     */
    private $attestationStatementSupportManager;

    private function getAttestationStatementSupportManager(): AttestationStatementSupportManager
    {
        if (!$this->attestationStatementSupportManager) {
            $this->attestationStatementSupportManager = new AttestationStatementSupportManager();
            $this->attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
            $this->attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport(
                $this->getDecoder()
            ));
            $this->attestationStatementSupportManager->add(new PackedAttestationStatementSupport());
        }

        return $this->attestationStatementSupportManager;
    }

    /**
     * @var null|AttestationObjectLoader
     */
    private $attestationObjectLoader;

    private function getAttestationObjectLoader(): AttestationObjectLoader
    {
        if (!$this->attestationObjectLoader) {
            $this->attestationObjectLoader = new AttestationObjectLoader(
                $this->getDecoder()
            );
        }

        return $this->attestationObjectLoader;
    }
}
