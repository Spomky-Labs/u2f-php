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

session_start();

// Retrieve the Registration passed to the device
$request = $_SESSION['fido_request'];
dump($request);

// Retrieve de data sent by the device
$data = $_GET['data'];
$json = json_decode($data, true);
dump($json);
$response = \U2FAuthentication\Fido\RegistrationResponse::create($json);
dump($response);

dump($response->isValid($request));
