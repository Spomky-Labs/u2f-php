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

use Base64Url\Base64Url;
use CBOR\Decoder;

class AttestationObjectParser
{
    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * AttestationObjectParser constructor.
     *
     * @param Decoder $decoder
     */
    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    /**
     * @param string $attestationObject
     *
     * @return array
     */
    public function parse(string $attestationObject): array
    {
        $decodedAttestationObject = Base64Url::decode($attestationObject);
        $stream = new StringStream($decodedAttestationObject);
        $data = $this->decoder->decode($stream);

        return $data->getNormalizedData();
    }
}
