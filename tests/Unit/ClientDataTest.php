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

namespace U2FAuthentication\Tests\Unit;

use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;
use U2FAuthentication\ClientData;

/**
 * @group Unit
 */
final class ClientDataTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid client data.
     */
    public function theClientDataIsNotBase64UrlEncoded()
    {
        ClientData::create(
            'foo'
        );
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid client data.
     */
    public function theClientDataIsNotAnArray()
    {
        ClientData::create(
            Base64Url::encode('foo')
        );
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid client data.
     */
    public function theClientDataDoesNotContainTheMandatoryKeys()
    {
        ClientData::create(
            Base64Url::encode(json_encode([]))
        );
    }

    /**
     * @test
     */
    public function theClientDataIsValid()
    {
        $data = json_encode([
            'typ'        => 'foo',
            'challenge'  => Base64Url::encode('bar'),
            'origin'     => 'here',
            'cid_pubkey' => 'none',
        ]);
        $client_data = ClientData::create(
            Base64Url::encode($data)
        );

        self::assertEquals('foo', $client_data->getType());
        self::assertEquals('bar', $client_data->getChallenge());
        self::assertEquals('here', $client_data->getOrigin());
        self::assertEquals('none', $client_data->getChannelIdPublicKey());
        self::assertEquals($data, $client_data->getRawData());
    }
}
