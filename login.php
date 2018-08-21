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

use U2FAuthentication\Fido2\PublicKeyCredentialRequestOptions;
use U2FAuthentication\Fido2\AuthenticationExtensionsClient;
use U2FAuthentication\Fido2\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;

session_start();

$extensions = new AuthenticationExtensionsClientInputs();
//$extensions->add(new AuthenticationExtensionsClient('exts', true));
$request = new PublicKeyCredentialRequestOptions(
    random_bytes(32),
    60000,
    null, //'localhost', //'My Application',
    [
            new PublicKeyCredentialDescriptor(
                'public-key',
                base64_decode('wpeVFZtUqnqy8nYUNUfH/+8LuZFT/+i3Gw6yQJ/0AqmiYYgMn5Ik80uBi61TzSSHEDFqR6gaROEUPRpJWHir7g==')
            )
    ],
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
    $extensions
);

$_SESSION['login'] = $request;

header('Content-Type: text/html');
?>

<html>
    <head>
        <title>Login</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($request) ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        publicKey.challenge = new Uint8Array(publicKey.challenge);
        publicKey.allowCredentials[0].id = new Uint8Array(publicKey.allowCredentials[0].id);
        //publicKey.user.id = new TextEncoder().encode(publicKey.user.id);
console.log(publicKey);
        navigator.credentials.get({publicKey})
            .then(function (data) {
                console.log(data);
                //window.location = "/request_post.php?data="+btoa(JSON.stringify(publicKeyCredential));
            });
    </script>
    </body>
</html>
