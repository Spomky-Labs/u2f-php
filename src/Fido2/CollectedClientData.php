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

class CollectedClientData
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var string
     */
    private $origin;

    /**
     * @var null|TokenBinding
     */
    private $tokenBinding;

    /**
     * CollectedClientData constructor.
     *
     * @param string            $type
     * @param string            $challenge
     * @param string            $origin
     * @param null|TokenBinding $tokenBinding
     */
    public function __construct(string $type, string $challenge, string $origin, ?TokenBinding $tokenBinding)
    {
        $this->type = $type;
        $this->challenge = $challenge;
        $this->origin = $origin;
        $this->tokenBinding = $tokenBinding;
    }

    /**
     * @param array $json
     *
     * @return CollectedClientData
     */
    public static function createFormJson(array $json): self
    {
        if (!array_key_exists('type', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('challenge', $json)) {
            throw new \InvalidArgumentException();
        }
        if (!array_key_exists('origin', $json)) {
            throw new \InvalidArgumentException();
        }
        if (array_key_exists('tokenBinding', $json)) {
            $tokenBinding = TokenBinding::createFormJson($json['tokenBinding']);
        } else {
            $tokenBinding = null;
        }

        return new self(
            $json['type'],
            $json['challenge'],
            $json['origin'],
            $tokenBinding
        );
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return string
     */
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @return string
     */
    public function getOrigin(): string
    {
        return $this->origin;
    }

    /**
     * @return null|TokenBinding
     */
    public function getTokenBinding(): ?TokenBinding
    {
        return $this->tokenBinding;
    }
}
