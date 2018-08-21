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

use U2FAuthentication\Fido\RegistrationRequest;

session_start();

$request = RegistrationRequest::create('https://localhost', []);

$_SESSION['fido_request'] = $request;

header('Content-Type: text/html');
?>

<html>
    <head>
        <title>Request</title>
    </head>
    <body>
    <script src="u2f-api.js"></script>
    <script>
        let request = <?php echo json_encode($request) ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }
        console.log(request);

        u2f.register(
            request.appId,
            request.registerRequests,
            request.registeredKeys,
            function(data) {
                switch (data.errorCode) {
                    case 0:
                        break;
                    case 4:
                        alert("This device is already registered.");
                        break;
                    default:
                        alert("U2F failed with error: " + data.errorCode);
                }
                window.location = "/fido_request_post.php?data="+JSON.stringify(data);
            }
        );
    </script>
    </body>
</html>
