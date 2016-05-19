<?php

namespace Afk11\EcSSH\Serializer;

use Afk11\EcSSH\Curves;
use Mdanter\Ecc\Crypto\Key\PublicKey;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Math\MathAdapterInterface;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;

class SshPublicKeySerializer
{
    /**
     * @var UncompressedPointSerializer
     */
    private $pointSerializer;

    /**
     * @var MathAdapterInterface
     */
    private $math;

    /**
     * SshPublicKeySerializer constructor.
     * @param UncompressedPointSerializer $pointSerializer
     */
    public function __construct(MathAdapterInterface $math, UncompressedPointSerializer $pointSerializer)
    {
        $this->math = $math;
        $this->pointSerializer = $pointSerializer;
    }

    /**
     * @param string $curveName
     * @param PublicKeyInterface $publicKey
     * @return string
     */
    public function serialize($curveName, PublicKeyInterface $publicKey)
    {
        $ecdsa = 'ecdsa-sha2-' . $curveName;
        $key = hex2bin($this->pointSerializer->serialize($publicKey->getPoint()));

        $serialized  = pack("N", strlen($ecdsa)) . $ecdsa;
        $serialized .= pack("N", strlen($curveName)) . $curveName;
        $serialized .= pack("N", strlen($key)) . $key;

        return base64_encode($serialized);
    }

    /**
     * @param $base64
     * @return array
     */
    public function unserialize($base64)
    {
        $binary = base64_decode($base64, true);
        if ($binary === false) {
            throw new \InvalidArgumentException('Invalid base64');
        }

        $values = [];
        $pos = 0;
        $end = strlen($binary);
        for ($i = 0; $i < 3; $i++) {
            if ($end - $pos < 4) {
                throw new \RuntimeException('Length marker too short');
            }
            $length = unpack("N", substr($binary, $pos, 4))[1];
            $pos += 4;

            if ($end - $pos < $length) {
                throw new \RuntimeException('Not enough data');
            }

            $value = substr($binary, $pos, $length);
            $pos += $length;
            $values[$i] = $value;
        }

        $curveName = $values[1];
        $pointHex = unpack("H*", $values[2])[1];
        $curve = Curves::curve($curveName);
        $generator = Curves::generator($curveName);
        $point = $this->pointSerializer->unserialize($curve, $pointHex);
        $publicKey = new PublicKey($this->math, $generator, $point);
        return [$curve, $publicKey];
    }
}
