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

class PublicKeyCredentialEntity implements \JsonSerializable
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var null|string
     */
    private $icon;

    /**
     * PublicKeyCredentialEntity constructor.
     *
     * @param string      $name
     * @param null|string $icon
     */
    public function __construct(string $name, ?string $icon)
    {
        $this->name = $name;
        $this->icon = $icon;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return null|string
     */
    public function getIcon(): ?string
    {
        return $this->icon;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        $json = [
            'name' => $this->name,
        ];
        if ($this->icon) {
            $json['icon'] = $this->icon;
        }

        return $json;
    }
}
