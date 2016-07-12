<?php

namespace Afk11\EcSSH\Tests;

use Afk11\EcSSH\EncryptedPrivateKey;
use Mdanter\Ecc\Curves\CurveFactory;

class EncryptedPrivateKeyTest extends AbstractTest
{
    public function testCreate()
    {
        $privateKey = CurveFactory::getGeneratorByName('nistp256')->getPrivateKeyFrom(gmp_init(100));
        $iv = random_bytes(16);
        $method = 'AES-128-CBC';
        $key = new EncryptedPrivateKey($privateKey, $method, $iv);
        $this->assertEquals($iv, $key->getIv());
        $this->assertEquals($method, $key->getMethod());
        $this->assertSame($privateKey, $key->getKey());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unknown cipher method
     */
    public function testInvalidCipher()
    {
        $privateKey = CurveFactory::getGeneratorByName('nistp256')->getPrivateKeyFrom(gmp_init(100));
        $iv = random_bytes(16);
        $method = 'not-a-known-cipher';
        new EncryptedPrivateKey($privateKey, $method, $iv);
    }
}
