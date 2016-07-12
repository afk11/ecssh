<?php

namespace Afk11\EcSSH\Pkcs8;


use Afk11\Pkcs5\Cipher\CipherParamsInterface;
use Afk11\Pkcs5\Digest\DigestParamsInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKey;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Math\GmpMathInterface;

class Pkcs8PrivateKey extends PrivateKey
{
    /**
     * @var DigestParamsInterface
     */
    private $kdfParams;

    /**
     * @var CipherParamsInterface
     */
    private $cipherParams;

    /**
     * Pkcs8PrivateKey constructor.
     * @param GmpMathInterface $math
     * @param DigestParamsInterface $kdfParams
     * @param CipherParamsInterface $cipherParams
     * @param PrivateKeyInterface $privateKey
     */
    public function __construct(GmpMathInterface $math, DigestParamsInterface $kdfParams, CipherParamsInterface $cipherParams, PrivateKeyInterface $privateKey)
    {
        $this->kdfParams = $kdfParams;
        $this->cipherParams = $cipherParams;
        parent::__construct($math, $privateKey->getPoint(), $privateKey->getSecret());
    }

    /**
     * @return DigestParamsInterface
     */
    public function getKdfParams()
    {
        return $this->kdfParams;
    }

    /**
     * @return CipherParamsInterface
     */
    public function getCipherParams()
    {
        return $this->cipherParams;
    }
}