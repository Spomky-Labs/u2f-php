Public Key Credential Creation
==============================

# Request Creation

To associate a device to a user, you need to instatiate a `PublicKeyCredentialCreationOptions` object.
This object will need:

* The Relaying Party data
* The User data
* A challenge (random binary string)
* A list of supported public key parameters (at least one)
* A timeout (optional)
* A list of public key credential to exclude from the registration process (optional)
* The Authenticator Selection Criteria (e.g. user presence requirement)
* Attestation conveyance preference
* Extensions (optional)

The `PublicKeyCredentialCreationOptions` object and all objects below are designed to be easily serialized into a JSON object.
This behaviour will ease the integration of your creation options e.g. when integrated into an HTML page (see example below).

## Relaying Party Entity

The Relaying Party Entity corresponds to your application details.

It needs 
* a name (required)
* an ID (required)
* an icon (optional)


```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;

$rpEntity = new PublicKeyCredentialRpEntity(
    'My Super Secured Application', //Name
    null,                           //Icon
    'foo.example.com'               //ID
);
```

## User Entity

The User Entity needs the same information as the Relaying Party plus a display name:

* a name (required)
* an ID (required)
* an icon (optional)
* a display name (optional)

The name corresponds to the username.
The name and the ID must be unique.

```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    null,                                   //Icon
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike'                           //Display name
);
```

## Challenge

The challenge is a random string that contains enough entropy to make guessing them infeasible.
It should be at least 16 bytes long.

```php
<?php

$challenge = random_bytes(32); // 32 bytes challenge
```

## Public Key Credential Parameters

The Public Key Credential Parameters is a list of allowed algorithms and key types.
This list must contain at least one element.

The order is very important. The authentication device will consider the first one in the list as the most important one.


```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;

$publicKeyCredentialParameters = [
    new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
    new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_RS256),
];
```

**Please note that at the moment the algorithms supported by this library are very limited.**
**We recommend to use only ES256.**

## Timeout

You can specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
This is treated as a hint, and may be overridden by the client.

We recommend to set 60 seconds (60000 milliseconds).

## Excluded Credentials

The user trying to register a device may have registered other devices.
To limit the creation of multiple credentials for the same account on a single authenticator.
You can then ignore these devices.

```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;

$excludedDevice = new PublicKeyCredentialDescriptor(
    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,      // Type of credential (usually 'public-key')
    $publicKeyId,                                                   // ID of the credential (given after creation process)
    [                                                               // Transport mode of the device (optional)
        PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
        PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE,
    ]
);

$excludedCredentials =[
    $excludedDevice
];
```

## Authenticator Selection Criteria

The `U2FAuthentication\Fido2\AuthenticatorSelectionCriteria` object is intended to select the appropriate authenticators to participate in the creation operation.

* Attachment: indicates if the device should be attached on the platform or not.
* Resident key: requirements regarding resident credentials.
* User presence: requirements regarding the user verification. Eligible authenticators are filtered and only capable of satisfying this requirement will interact with the user.

```php
<?php
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;

$excludedDevice = new AuthenticatorSelectionCriteria(
    AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,      // Attachment mode (default=null):
                                                                            //   * 'platform' (const AUTHENTICATOR_ATTACHMENT_PLATFORM), 'cross-platform' or null
                                                                            //   * 'cross-platform' (const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM)
                                                                            //   * null (no preference)
    false,                                                                  // Resident key (default=USER_VERIFICATION_REQUIREMENT_PREFERRED)
    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED // User presence (default=null):
                                                                            //   * 'required' (const USER_VERIFICATION_REQUIREMENT_REQUIRED)
                                                                            //   * 'preferred' (const USER_VERIFICATION_REQUIREMENT_PREFERRED)
                                                                            //   * 'discouraged' (const USER_VERIFICATION_REQUIREMENT_DISCOURAGED)
);
```

## Attestation Conveyance

This parameter specify the preference regarding the attestation conveyance during credential generation.
There are 3 possible values:

* none: the Relying Party is not interested in authenticator attestation. For example, in order to potentially avoid having to obtain user consent to relay identifying information to the Relying Party, or to save a roundtrip to an Attestation CA.
* indirect: the Relying Party prefers an attestation conveyance yielding verifiable attestation statements, but allows the client to decide how to obtain such attestation statements. The client MAY replace the authenticator-generated attestation statements with attestation statements generated by an Anonymization CA, in order to protect the user’s privacy, or to assist Relying Parties with attestation verification in a heterogeneous ecosystem. There is no guarantee that the Relying Party will obtain a verifiable attestation statement in this case. For example, in the case that the authenticator employs self attestation.
* direct: the Relying Party wants to receive the attestation statement as generated by the authenticator.

Predefined constants are available through the `PublicKeyCredentialCreationOptions` class:

* `PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE`
* `PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT`
* `PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT`

## Extensions

The mechanism for generating public key credentials, as well as requesting and generating Authentication assertions,
can be extended to suit particular use cases.
Each case is addressed by defining a registration extension.

The extensions are not yet supported by this library, but is ready to handle them.

The Following example is totally fictive.

```php
<?php
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtension;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

$locationExtension = new AuthenticationExtension('loc', true); // Location of the device required during the creation process

$creationExtensions = new AuthenticationExtensionsClientInputs();
$creationExtensions->add($locationExtension);
```

## Example

The following example is a possible Public Key Creation page for a dummy user "@cypher-Angel-3000".

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtension;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;
use U2FAuthentication\Fido2\PublicKeyCredentialCreationOptions;
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

// RP Entity
$rpEntity = new PublicKeyCredentialRpEntity(
    'My Super Secured Application', //Name
    null,                           //Icon
    'foo.example.com'               //ID
);

// User Entity
$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    null,                                   //Icon
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike'                           //Display name
);

// Challenge
$challenge = random_bytes(32);

// Public Key Credential Parameters
$publicKeyCredentialParametersList = [
    new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
];

// Timeout
$timeout = 20000;

// Devices to exclude
$excludedPublicKeyDescriptors = [
    new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, 'ABCDEFGH'),
];

// Authenticator Selection Criteria
$authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
    null,
    false,
    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
);

// Extensions
$extensions = new AuthenticationExtensionsClientInputs();
$extensions->add(new AuthenticationExtension('loc', true));

$publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
    $rpEntity,
    $userEntity,
    $challenge,
    $publicKeyCredentialParametersList,
    $timeout,
    $excludedPublicKeyDescriptors,
    $authenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    $extensions
);
?>

<html>
    <head>
        <meta charset="UTF-8" />
        <title>Request</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($publicKeyCredentialCreationOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        publicKey.challenge = Uint8Array.from(window.atob(publicKey.challenge), c=>c.charCodeAt(0));
        publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), c=>c.charCodeAt(0));
        if (publicKey.excludeCredentials) {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map(function(data) {
                return {
                    ...data,
                    'id': Uint8Array.from(window.atob(data.id), c=>c.charCodeAt(0))
                };
            });
        }

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
                window.location = '/request_post?data='+btoa(JSON.stringify(publicKeyCredential));
            }, function (error) {
                console.log(error); // Example: timeout, interaction refused...
            });
    </script>
    </body>
</html>
```

**It is important to store this request in the session for the next step.**
**This request object will be needed to check the response from the device.**

# Response Handling

The way you receive this response is out of scope of this library.
In the previous example, the data is part of the query string, but it can be done through a POST request body or a request header.

What you receive must be a JSON object that looks like as follow:

```json
{
    "id":"KVb8CnwDjpgAo[…]op61BTLaa0tczXvz4JrQ23usxVHA8QJZi3L9GZLsAtkcVvWObA",
    "type":"public-key",
    "rawId":"KVb8CnwDjpgAo[…]rQ23usxVHA8QJZi3L9GZLsAtkcVvWObA==",
    "response":{
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJQbk1hVjBVTS[…]1iUkdHLUc4Y3BDSdGUifQ==",
        "attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSj[…]YcGhf"
    }
}
```

There are two steps to perform with this object:

* Data loading
* Verification against the creation options and the challenge set above

## Prerequisites

You will need the following components before loading or verifying the data:

* A credential repository
* A CBOR Decoder (binary format used by the Webauthn protocol)
* An Attestation Statement Support Manager and at least one Attestation Statement Support object
* An Attestation Object Loader
* A Public Key Credential Loader
* An Authenticator Attestation Response Validator

That’s a lot off classes! But don’t worry, as their configuration is the same for all your application, you just have to set them once.

### Credential Repository

This repository must implement `U2FAuthentication\Fido2\CredentialRepository`.
It will retrieve the credentials, key IDs and update devices counters when needed.

You can implement the mrequired methods the way you want: Doctrine ORM, file storage…

### CBOR Decoder

Don’t panic! This library uses [`spomky-labs/cbor-php`](https://github.com/Spomky-Labs/cbor-php) and there is nothing complicated to do:

```php
<?php

declare(strict_types=1);

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;

$decoder = new Decoder(new OtherObjectManager(), new TagObjectManager());
```

That’s all!

### Attestation Statement Support Manager

At the moment, only 3 Attestation Statement types are supported:

* none
* fido-u2f
* packed

We highly recommend to use them all.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;
use U2FAuthentication\Fido2\AttestationStatement\FidoU2FAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\NoneAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\PackedAttestationStatementSupport;

$attestationStatementSupportManager = new AttestationStatementSupportManager();
$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
$attestationStatementSupportManager->add(new PackedAttestationStatementSupport());
```

### Attestation Object Loader

This object will load the Attestation statements received from the devices.
It will need the CBOR Decoder an dependency.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;

$attestationObjectLoader = new AttestationObjectLoader($decoder);
```

### Public Key Credential Loader

This object will load the Public Key using from the Attestation Object.
It will need the CBOR Decoder an dependency.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\PublicKeyCredentialLoader;

$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);
```

### Authenticator Attestation Response Validator

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAttestationResponseValidator;

$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
    $attestationStatementSupportManager,
    $credentialRepository
);
```

## Data Loading

Now that all components are set, we can load the data we received.
For that, we just need the *Public Key Credential Loader* (variable `$publicKeyCredential`).

```php
$data = '
{
    "id":"KVb8CnwDjpgAo[…]op61BTLaa0tczXvz4JrQ23usxVHA8QJZi3L9GZLsAtkcVvWObA",
    "type":"public-key",
    "rawId":"KVb8CnwDjpgAo[…]rQ23usxVHA8QJZi3L9GZLsAtkcVvWObA==",
    "response":{
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJQbk1hVjBVTS[…]1iUkdHLUc4Y3BDSdGUifQ==",
        "attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSj[…]YcGhf"
    }
}';

$publicKeyCredential = $publicKeyCredentialLoader->load($data);
```

If no exception is thrown, the `$publicKeyCredential` is a `U2FAuthentication\Fido2\PublicKeyCredential` object.

You can call the following methods:

* `$publicKeyCredential->getId()`: the ID of the public key (base64url safe encoded)
* `$publicKeyCredential->getRawId()`: same as above, but as a binary string
* `$publicKeyCredential->getType()`: usually 'public-key'
* `$publicKeyCredential->getPublicKeyCredentialDescriptor()`: returns the descriptor of the key.
* `$publicKeyCredential->getResponse()`: the authenticator response

We need now to ensure that the authenticator response is of type `AuthenticatorAttestationResponse`.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAttestationResponse;

$authenticatorAttestationResponse = $publicKeyCredential->getResponse();
if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
    //e.g. process here with a redirection to the public key creation page. 
}
```

## Response Verification

Now we have a fully loaded Authenticator Attestation Response.
The next step is the verification against the Creation Options we created earlier.

The Authenticator Attestation Response Validator will check everything for you: challenge, origin, attestation statement and much more.
In the following example, the variable `$publicKeyCredentialCreationOptions` corresponds to the Public Key Credential Creation Options object we created in the previous step.

```php
$authenticatorAttestationResponseValidator->check(
    $authenticatorAttestationResponse,
    $publicKeyCredentialCreationOptions
);
```

If no exception is thrown, the response is valid and you can storeand associate those to the user:

* The Public Key Descriptor: `$publicKeyCredential->getPublicKeyCredentialDescriptor()`
* The Attested Credential Data: `$authenticatorAttestationResponse->getAttestationObject()->getAuthData()->getAttestedCredentialData()`

### Public Key Descriptor

The public key descriptor is an instance of `U2FAuthentication\Fido2\PublicKeyCredentialDescriptor`.
This object can be retrieved using the method `$publicKeyCredential->getPublicKeyCredentialDescriptor()`.


```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAttestationResponse;
use U2FAuthentication\Fido2\PublicKeyCredential;


/** PublicKeyCredential $publicKeyCredential */
$publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();


/** @var AuthenticatorAttestationResponse $authenticatorAttestationResponse */
$attestedCredentialData = $authenticatorAttestationResponse->getAttestationObject()->getAuthData()->getAttestedCredentialData();
```


