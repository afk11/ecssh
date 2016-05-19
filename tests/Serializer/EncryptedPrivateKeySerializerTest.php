<?php

namespace Afk11\EcSSH\Tests\Serializer;

use Afk11\EcSSH\Curves;
use Afk11\EcSSH\EncryptedPrivateKey;
use Afk11\EcSSH\Serializer\EncryptedPrivateKeySerializer;
use Afk11\EcSSH\Tests\AbstractTest;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;

class EncryptedPrivateKeySerializerTest extends AbstractTest
{
    public function getVectors()
    {
        return [
            [
                'nistp256',
                '79671457102618293027161681574876575359411263728823893534019149682140678748846',
                '0D50C3AFF6A2FB140530DC591E34C559',
                'AES-128-CBC',
                'a long password',
                "-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0D50C3AFF6A2FB140530DC591E34C559

jDe/qW43lboKbCBvWLLgOWx0dE4qSzIyENJRdxOpRab7xBmAwaxcFts5UnUaYgjy
6yjhgtkelCFglcWJbex6HpPjHBvO9qrxVMxr6zG9/aHNTRlaOfC5dDEeHpuwxiNt
oxOb50JB5mnalaA0zVj8A203mdAXHYNPWxvAf+Icf1Q=
-----END EC PRIVATE KEY-----"
            ],
            [
                'nistp384',
                '31523166834585610185483970060696071688575479003456582028328734331639173407912699615116655719599135718261740123767992',
                '13AF631CBEC7C6DB2A9AAEC72D27882F', // iv
                'AES-128-CBC', // method
                'testpassword', // password
                "-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,13AF631CBEC7C6DB2A9AAEC72D27882F

Rdg215FRLMxetp8hxe93r44McjyyoZfAZH2dXemSv/P0Sk0DmCQAWkzLyz3grKO4
UZEZlTet7vx3Vq6dUjCDfczxLaZ9SBtdAUr/7ZREyUGqimeYMQ0Bt7cw6V1buYSN
Zm49yeVTunipWfrY8ypd22n2NcsWt5NieNlwz7KHCgc9tWli1x0rBF5ZbTSRpWhN
R6NR4Q9gwT8XuW918uflLXf4rptDAY8bj8DwZ7ZaGeg=
-----END EC PRIVATE KEY-----"
            ],
            [
                'nistp521',
                '5562791306265635975605275615547097751326269797038072671652259203219235517191351110361006569406037562645791129337001085194048117479825370871842485696203375735',
                '04A7603189B38885DECA5E73DA0D4C79',
                'AES-128-CBC',
                'different',
                "-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,04A7603189B38885DECA5E73DA0D4C79

XsFSN2PNOsg0ImiH/A38R4wG6fQA2HFJHFvIanhP68pyypkB/on+pCwkMuXvwy7s
c1mbA+De6w+jLiZf2EHZMjMlrugFLsl6Js+6GN3XlLum8DnQNgtSFmdonkcOFPy7
6RyVZzUzmrn7FmgYNUfT5pgGwLlpx7mowUhV72v3s1MFGaCLPTj4pSDx3AkxpX3f
EDZhDsGRteWRvuBtR7sS5raOpYZTy7lug6TpJioVbWa7awNHuy26kJP8cgBTrwyc
JAMKCgCmEqew2Wd7KobexGVF6tmiHn4+GWTqg7rq3EA=
-----END EC PRIVATE KEY-----"
            ]
        ];
    }

    /**
     * @dataProvider getVectors
     * @param $curveName
     * @param $multiplier
     * @param $iv
     * @param $method
     * @param $password
     * @param $expectedPriv
     */
    public function testSerialize($curveName, $multiplier, $iv, $method, $password, $expectedPriv)
    {
        $iv = pack("H*", $iv);

        /** @var GeneratorPoint $generator */
        $generator = Curves::generator($curveName);
        $privateKey = $generator->getPrivateKeyFrom($multiplier);

        $cryptKey = new EncryptedPrivateKey($privateKey, $method, $iv);
        $this->assertSame($privateKey, $cryptKey->getKey());
        $this->assertEquals($method, $cryptKey->getMethod());
        $this->assertEquals($iv, $cryptKey->getIv());

        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serialized = $serializer->serialize($cryptKey, $password);

        $this->assertEquals($expectedPriv, $serialized);

        $parsed = $serializer->unserialize($expectedPriv, $password);
        $this->assertTrue($parsed->equals($cryptKey));
    }

    public function testSerializeEncFail()
    {
        $iv = random_bytes(16);
        $method = 'AES-128-CBC';
        $password = false;

        /** @var GeneratorPoint $generator */
        $generator = Curves::generator('nistp256');
        $privateKey = $generator->getPrivateKeyFrom(1923123);

        $cryptKey = new EncryptedPrivateKey($privateKey, $method, $iv);
        $this->assertSame($privateKey, $cryptKey->getKey());
        $this->assertEquals($method, $cryptKey->getMethod());
        $this->assertEquals($iv, $cryptKey->getIv());

        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->serialize($cryptKey, $password);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseDekInfo()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseDekInfo('a');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseDekInfo2()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseDekInfo('notacipher,' . bin2hex(random_bytes(16)));
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseDekInfo3()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseDekInfo('AES-128-CBC,a');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseDekInfo4()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseDekInfo('AES-128-CBC,abababababababababababababababgg');
    }

    public function testParsesDekInfo()
    {
        $method = 'AES-128-CBC';
        $iv = 'abababababababababababababababab';

        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        list ($pm, $piv) = $serializer->parseDekInfo($method.','.$iv);

        $this->assertEquals($method, $pm);
        $this->assertEquals(hex2bin($iv), $piv);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseProcTypeFail()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseProcType('4');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseProcTypeFail2()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseProcType('3,ENCRYPTED');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testParseProcTypeFail3()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->parseProcType('4,WRONG');
    }

    public function testParsesProcTypeFail()
    {
        $int = 4;
        $status = 'ENCRYPTED';

        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        list ($pi, $ps) = $serializer->parseProcType($int.','.$status);
        $this->assertEquals($int, $pi);
        $this->assertEquals($status, $ps);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testSerializeFailsToEncrypt()
    {
        /** @var GeneratorPoint $generator */
        $generator = Curves::generator('nistp256');
        $privateKey = $generator->getPrivateKeyFrom('1');

        $method = 'not-a-method';
        $iv = random_bytes(16);
        $cryptKey = new EncryptedPrivateKey($privateKey, $method, $iv);
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->serialize($cryptKey, 'password');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testUnserializeFail()
    {
        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->unserialize('', '');
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Decryption failed
     */
    public function testDecryptionFailure()
    {
        $key = '-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,ABABABABABABABABABABABABABABABAB

dGhpcyBpcyBpbnZhbGlkIGRhdGE=
-----END EC PRIVATE KEY-----';

        $adapter = EccFactory::getAdapter();
        $serializer = new EncryptedPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
        $serializer->unserialize($key, 'password');
    }
}
