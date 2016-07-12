<?php

namespace Afk11\EcSSH;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Util\BinaryString;

class EncryptedPrivateKey
{
    /**
     * @var PrivateKeyInterface
     */
    private $key;

    /**
     * @var string
     */
    private $method;

    /**
     * @var string
     */
    private $iv;

    /**
     * EncryptedPrivateKey constructor.
     * @param PrivateKeyInterface $key
     * @param string $method
     * @param string $iv
     */
    public function __construct(PrivateKeyInterface $key, $method, $iv)
    {
        $methods = openssl_get_cipher_methods();
        if (!in_array($method, array_values($methods))) {
            throw new \RuntimeException('Unknown cipher method');
        }

        $this->key = $key;
        $this->method = $method;
        $this->iv = $iv;
    }

    /**
     * @return PrivateKeyInterface
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }

    /**
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @param EncryptedPrivateKey $that
     * @return bool
     */
    public function equals(EncryptedPrivateKey $that)
    {
        return $this->getMethod() === $that->getMethod()
            && $this->getIv() === $that->getIv()
            && BinaryString::constantTimeCompare(gmp_strval($this->getKey()->getSecret(), 10), gmp_strval($that->getKey()->getSecret(), 10));
    }
}
