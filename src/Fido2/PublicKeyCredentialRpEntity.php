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

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    /**
     * @var null|string
     */
    private $id;

    /**
     * PublicKeyCredentialRpEntity constructor.
     */
    public function __construct(string $name, ?string $icon, ?string $id)
    {
        parent::__construct($name, $icon);
        $this->id = $id;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        if ($this->id) {
            $json['id'] = $this->id;
        }

        return $json;
    }
}
