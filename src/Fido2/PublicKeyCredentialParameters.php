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

class PublicKeyCredentialParameters implements \JsonSerializable
{
    public const ALGORITHM_ES256 = -7;
    public const ALGORITHM_RS256 = -257;

    /**
     * @var string
     */
    private $type;

    /**
     * @var int
     */
    private $alg;

    /**
     * PublicKeyCredentialParameters constructor.
     *
     * @param string $type
     * @param int    $alg
     */
    public function __construct(string $type, int $alg)
    {
        $this->type = $type;
        $this->alg = $alg;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return int
     */
    public function getAlg(): int
    {
        return $this->alg;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg'  => $this->alg,
        ];
    }
}
