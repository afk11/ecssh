<?php

namespace Afk11\EcSSH\Tests\Serializer;

use Afk11\EcSSH\Curves;
use Afk11\EcSSH\Serializer\SshPublicKeySerializer;
use Afk11\EcSSH\Tests\AbstractTest;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;

class SshPublicKeySerializerTest extends AbstractTest
{
    public function getVectors()
    {
        return [
            ['nistp256', '4876243288044956869752490633974263156412970895256340761077418311897128719458', 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMwFaQWf8s0bJV9T91w03vqkuDYtnhY+WCMK7XCP0YzOaclsU9SsSs44TtpG1NyK2Bdie52OLI4HPNQZ4GROK7o='],
            ['nistp384', '23193196491782318861589410894238565866753943550468062869741186581201856549072727171688320415467779841861997710492377', 'AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBF51G6q8ALMnNGuYisPz/3BO82bKsrBXx9NVGbJ755frwgrJXIFAaPW8Lz+1oVAGVbrSXw/i3iVtaB5w3j7QFIsJut9JHUEDmrUznGQUCNWekPi2QpSe+Ba4gJwlaE/a1A=='],
            ['nistp521', '861081600125866201821384778324213967876363666157530648199748953827931681941707028894584179028709211248639832989118504506454517167940985636081010061012908607', 'AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFNvza8C+BIvNZAWrQEGlqp94B9ZcDERR/9+alWV/AyLRLAeftPnOFPTiNr4mMd9+wU2egERrsIcFEUQ9AT/FkLQAEjfG3Etc4GzlzJuhX0AZ48v917MCUQjAMJU7i9jbRuJiLqCn8sPBeRV2q0vmDoMmMlYegXL20MVmGurDOd6kqg3Q==']
        ];
    }

    /**
     * @dataProvider getVectors
     * @param string $curveName
     * @param string|int $multiplier
     * @param string $expectedPub
     */
    public function testSerialize($curveName, $multiplier, $expectedPub)
    {
        /** @var GeneratorPoint $generator */
        $generator = Curves::generator($curveName);
        $privateKey = $generator->getPrivateKeyFrom(gmp_init($multiplier, 10));
        $public = $privateKey->getPublicKey();

        $adapter = EccFactory::getAdapter();
        $serializer = new SshPublicKeySerializer($adapter, new UncompressedPointSerializer($adapter));
        $serialized = $serializer->serialize($curveName, $public);
        $this->assertEquals($expectedPub, $serialized);
        
        list ($curve, $publicKey) = $serializer->unserialize($serialized);
        $this->assertTrue($public->getPoint()->equals($publicKey->getPoint()));
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough data
     */
    public function testInvalidData()
    {
        $data = base64_encode(pack("N", 4) . "II");
        $adapter = EccFactory::getAdapter();
        $serializer = new SshPublicKeySerializer($adapter, new UncompressedPointSerializer($adapter));
        $serializer->unserialize($data);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Length marker too short
     */
    public function testInvalidData2()
    {
        $data = base64_encode("\x00\x00\x03");
        $adapter = EccFactory::getAdapter();
        $serializer = new SshPublicKeySerializer($adapter, new UncompressedPointSerializer($adapter));
        $serializer->unserialize($data);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid base64
     */
    public function testInvalidBase64Data()
    {
        $data = "ab$";
        $adapter = EccFactory::getAdapter();
        $serializer = new SshPublicKeySerializer($adapter, new UncompressedPointSerializer($adapter));
        $serializer->unserialize($data);
    }
}
