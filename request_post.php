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

require_once 'vendor/autoload.php';

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;
use U2FAuthentication\Fido2\AttestationStatement\FidoU2FAttestationStatement;
use U2FAuthentication\Fido2\AttestationStatement\NoneAttestationStatement;
use U2FAuthentication\Fido2\PublicKeyCredentialLoader;

session_start();

// Retrieve the Options passed to the device
$request = $_SESSION['request'];
dump($request);

// Retrieve de data sent by the device
$data = base64_decode($_GET['data']);

// Create a CBOR Decoder object
$otherObjectManager = new OtherObjectManager();
$tagObjectManager = new TagObjectManager();
$decoder = new Decoder($tagObjectManager, $otherObjectManager);

$attestationStatementSupportManager = new AttestationStatementSupportManager();
$attestationStatementSupportManager->add(new NoneAttestationStatement());
$attestationStatementSupportManager->add(new FidoU2FAttestationStatement());

$attestationObjectLoader = new AttestationObjectLoader($decoder);
$publicKeyCredentialLoader = new PublicKeyCredentialLoader($decoder, $attestationObjectLoader);

$publicKeyCredential = $publicKeyCredentialLoader->load($data);
dump($publicKeyCredential);

/* To Be Done */
$publicKeyCredentialLoader->isValid($publicKeyCredential, $request);
