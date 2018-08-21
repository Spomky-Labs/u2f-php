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

use U2FAuthentication\Fido2\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;
use U2FAuthentication\Fido2\PublicKeyCredentialCreationOptions;
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

session_start();

$request = new PublicKeyCredentialCreationOptions(
    new PublicKeyCredentialRpEntity('My Application', null, 'localhost'),
    new PublicKeyCredentialUserEntity('test@foo.com', null, 'USER_ID', 'Test PublicKeyCredentialUserEntity'),
    random_bytes(32),
    [new PublicKeyCredentialParameters('public-key', -7)],
    60000,
    [],
    new AuthenticatorSelectionCriteria(
        null,
            false,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
    ),
    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
    new AuthenticationExtensionsClientInputs()
);

$_SESSION['request'] = $request;

header('Content-Type: text/html');
?>

<html>
    <head>
        <title>Request</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($request) ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        publicKey.challenge = new Uint8Array(publicKey.challenge);
        publicKey.user.id = new TextEncoder().encode(publicKey.user.id);

        navigator.credentials.create({publicKey})
            .then(function (data) {
                let publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject))
                    }
                };
                window.location = "/request_post.php?data="+btoa(JSON.stringify(publicKeyCredential));
            });
    </script>
    </body>
</html>
