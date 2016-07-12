<?php

namespace Afk11\EcSSH\Serializer;


use Afk11\EcSSH\Pkcs8\Pkcs8PrivateKey;
use Afk11\Pkcs5\Cipher\Crypter;
use Afk11\Pkcs5\Digest\Digester;
use Afk11\Pkcs5\Serializer\Pkcs5v2Serializer;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Math\MathAdapterFactory;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;

class Pkcs8Serializer
{
    const VERSION = 1;

    /**
     * @var DerPrivateKeySerializer
     */
    private $serializer;

    /**
     * @var \Mdanter\Ecc\Math\DebugDecorator|GmpMathInterface
     */
    private $adapter;
    
    /**
     * @var Crypter
     */
    private $crypter;

    /**
     * @var Digester
     */
    private $digester;
    
    /**
     * PKCS8Serializer constructor.
     * @param DerPrivateKeySerializer|null $serializer
     * @param GmpMathInterface|null $adapter
     */
    public function __construct(DerPrivateKeySerializer $serializer = null, GmpMathInterface $adapter = null)
    {
        $this->serializer = $serializer ?: new DerPrivateKeySerializer();
        $this->adapter = $adapter ?: MathAdapterFactory::getAdapter();
        $this->crypter = new Crypter();
        $this->digester = new Digester();
        $this->pkcs5 = new Pkcs5v2Serializer();
    }

    /**
     * {@inheritDoc}
     * @see \Mdanter\Ecc\Serializer\PrivateKeySerializerInterface::serialize()
     */
    public function getPrivateKeyInfo(PrivateKeyInterface $key)
    {
        $keyData = $this->serializer->serialize($key);
        $privateKeyInfo = new Sequence(
            new Integer(self::VERSION),
            new Sequence(
                new ObjectIdentifier(DerPublicKeySerializer::X509_ECDSA_OID),
                CurveOidMapper::getCurveOid($key->getPoint()->getCurve())
            ),
            new OctetString(unpack("H*", $keyData)[1])
        );

        return $privateKeyInfo->getBinary();
    }

    /**
     * @param Pkcs8PrivateKey $privateKey
     * @param string $password
     * @return Sequence
     */
    public function getEncryptedPrivateKeyInfo(Pkcs8PrivateKey $privateKey, $password)
    {
        $digestParams = $privateKey->getKdfParams();
        $cipherParams = $privateKey->getCipherParams();
        $pkcs5Info = $this->pkcs5->serialize($digestParams, $cipherParams);

        $encKey = $this->digester->digest($password, $digestParams);
        $data = $this->getPrivateKeyInfo($privateKey);
        $cipherText = $this->crypter->encrypt($data, $encKey, $cipherParams);

        return new Sequence(
            $pkcs5Info,
            new OctetString(unpack("H*", $cipherText)[1])
        );
    }

    /**
     * @param Pkcs8PrivateKey $privateKey
     * @param string $password
     * @return Sequence
     */
    public function serialize(Pkcs8PrivateKey $privateKey, $password)
    {
        $info = $this->getEncryptedPrivateKeyInfo($privateKey, $password);
        return $info;
    }
}