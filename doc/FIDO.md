Universal 2nd Factor (U2F)
==========================

This library can handle U2F requests and responses for both registration and signature verification processes.

The registration process allows a user to register a new token. This token will compute a challenge and, if succeeded, the key handler can be associated to the user account.

The signature verification process will ask a user to sign a challenge. If the challenge is correcly signed with one of a registered key, then the user can be considered as authenticated.

# Registration

## Request Creation

The `RegistrationRequest` class will prepare the request according to the application ID.

```php
<?php
use U2FAuthentication\Fido\RegistrationRequest;

$registrationRequest = RegistrationRequest::create(
    'https://www.example.com' //Application ID. Usually the application URL
);
```

If the user requesting a registration already registered some keys, you can pass a list of
`U2FAuthentication\Fido\RegisteredKey` objects as second argument

```php
<?php
use U2FAuthentication\Fido\RegistrationRequest;

$registrationRequest = RegistrationRequest::create(
    'https://www.example.com',
    $registeredKeys            //List of registered keys
);
```

The `$registrationRequest` can be serialized into JSON to ease its integration into a HTML page.

**It is important to store this request in the session for the next step.**
**This request object will be needed to check the response from the U2F device.**

Hereafter an example of registration page.

```php
<?php
use U2FAuthentication\Fido\RegistrationRequest;

$registrationRequest = RegistrationRequest::create(
    'https://www.example.com' //Application ID. Usually the application URL
);

$_SESSION['u2f_registration_request'] = $registrationRequest;
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Key Registration</title>
    </head>
    <body>
        <h1>New key for user "FOO"</h1>
        TO BE WRITTEN
    </body>
</html> 
```

## Response Handling

The U2F device will compute the challenge sent in the previous step and will issue a registration response.
The way you receive this response is out of scope of this library. For example, it can be done through a POST request body, a request header or in the quesry string.

In the following examples, we consider the variable `$computedRequest` contains the raw data from the U2F device.

```php
<?php
use U2FAuthentication\Fido\RegistrationResponse;

$registrationResponse = RegistrationResponse::create(
    $computedRequest
);
```

If no exception is thrown, the variable `$registrationResponse` contains the loaded registration response.
This object contains a lot of useful data such as the client data or the signature, but the most important information is the registered key.

This key is a `U2FAuthentication\Fido\RegisteredKey` object.

```php
<?php

$registeredKey = $registrationResponse->getRegisteredKey();
$registeredKey->getVersion(); // Returns "U2F_V2"
$registeredKey->getKeyHandler(); // Returns a U2FAuthentication\Fido\KeyHandler object
$registeredKey->getPublicKey(); // Returns a U2FAuthentication\Fido\ PublicKey object
$registeredKey->getPublicKeyAsPem(); // Returns the public key using the PEM format
$registeredKey->getAttestationCertificate(); // Returns the attestation certificate of the U2F device
```

We now need to check if the response is valid against the registration request.

```php
<?php
use U2FAuthentication\Fido\RegistrationResponse;

$registrationRequest = $_SESSION['u2f_registration_request']; // We retreive the registration request
$registrationResponse = RegistrationResponse::create(
    $computedRequest
);

$isValid = $registrationResponse->isValid($registrationRequest);
```

If the variable `&isValid` is `true`, you can safely associate the registered key to the user.

**TODO: DATA TO BE STORED SHOULD BE DESCRIBED.**

### Device Registration Restrictions

#### Vendor Verification

In some cases, you may need to restrict the registered U2F devices to a limited set of vendors.
This can be acheived using the optional root attestation certificates passed as second argument of the `isValid` method.
In the following example, we will only allow devices [manufactured by Yubico](https://developers.yubico.com/U2F/Attestation_and_Metadata/).

> The root attestation certificates are not managed here. Please ask the manufacturer to provide it.

```php
<?php

$manufacturerCertificates = [
    __DIR__.'/certificates/yubico.crt',
];

$isValid = $registrationResponse->isValid(
  $registrationRequest,
  $manufacturerCertificates
);
```

With this manufacturer certificates list, all devices from Yubico will be allowed otherwise rejected.

#### Other Verifications

You can also load the attestation certificate from the registered key object (method `$registeredKey->getAttestationCertificate()`)
and check other parameters like the manufacture date or the serial number of the device contained in the certificate.
