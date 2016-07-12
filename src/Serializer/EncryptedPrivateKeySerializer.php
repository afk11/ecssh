<?php

namespace Afk11\EcSSH\Serializer;

use Afk11\EcSSH\EncryptedPrivateKey;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;

/**
 * Class EncryptedPrivateKeySerializer
 * Implements same structure as DerPrivateKeySerializer (rfc5915)
 * using RFC1421 headers
 *
 * @link https://tools.ietf.org/html/rfc1421
 * @package Afk11\EcSSH\Serializer
 */
class EncryptedPrivateKeySerializer
{
    /**
     * @var DerPrivateKeySerializer
     */
    private $derSerializer;

    /**
     * EncryptedPrivateKeySerializer constructor.
     * @param DerPrivateKeySerializer $derSerializer
     */
    public function __construct(DerPrivateKeySerializer $derSerializer)
    {
        $this->derSerializer = $derSerializer;
    }

    /**
     * @param EncryptedPrivateKey $key
     * @param string $password
     * @return string
     */
    public function serialize(EncryptedPrivateKey $key, $password)
    {
        $privateKey = $key->getKey();
        $iv = $key->getIv();
        $method = $key->getMethod();
        $plaintext = $this->derSerializer->serialize($privateKey);

        $key = md5($password . substr($iv, 0, 8), true);
        $ciphertext = openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv);

        if (false === $ciphertext) {
            throw new \RuntimeException('Failed to encrypt key');
        }

        return "-----BEGIN EC PRIVATE KEY-----" . "\x0a".
        "Proc-Type: 4,ENCRYPTED". "\x0a" .
        "DEK-Info: ".strtoupper($method).",".strtoupper(unpack("H*", $iv)[1])."\x0a\x0a" .
        implode("\x0a", str_split(base64_encode($ciphertext), 64)) ."\x0a" .
        "-----END EC PRIVATE KEY-----";
    }

    /**
     * @param string $string
     * @return array
     */
    public function parseDekInfo($string)
    {
        $dek = explode(",", $string);
        if (count($dek) !== 2) {
            throw new \RuntimeException('Malformed DEK-Info');
        }

        $cipher = $dek[0];
        $iv = $dek[1];

        if (!in_array($cipher, openssl_get_cipher_methods())) {
            throw new \RuntimeException('Unknown cipher method');
        }

        if (strlen($iv) / 2 !== openssl_cipher_iv_length($cipher)) {
            throw new \RuntimeException('Bad IV length');
        }

        if (!ctype_xdigit($iv)) {
            throw new \RuntimeException('Bad IV');
        }

        $iv = pack("H*", $iv);

        return [$cipher, $iv];
    }

    /**
     * @param string $string
     * @return array
     */
    public function parseProcType($string)
    {
        $proc = explode(",", $string);
        if (count($proc) !== 2) {
            throw new \RuntimeException('Malformed Proc-Type');
        }

        $int = $proc[0];
        if ($int !== '4' || $proc[1] !== 'ENCRYPTED') {
            throw new \RuntimeException("Invalid Proc-Type: doesn't indicate encryption");
        }

        return [$int, $proc[1]];
    }

    /**
     * @param string $data
     * @param string $password
     * @return EncryptedPrivateKey
     */
    public function unserialize($data, $password)
    {
        $comments = [];
        $short = '';
        foreach (explode("\n", $data) as $line) {
            if (strpos($line, ":") !== false) {
                $comment = explode(":", $line);
                if (count($comment) === 2) {
                    $comments[$comment[0]] = trim($comment[1]);
                }
            } else {
                $short .= $line."\n";
            }
        }

        if (!isset($comments['DEK-Info']) || !isset($comments['Proc-Type'])) {
            throw new \RuntimeException('Missing headers for encryption');
        }

        list ($cipher, $iv) = $this->parseDekInfo($comments['DEK-Info']);
        list ($proc1, $proc2) = $this->parseProcType($comments['Proc-Type']);

        $short = str_replace('-----BEGIN EC PRIVATE KEY-----', '', $short);
        $short = str_replace('-----END EC PRIVATE KEY-----', '', $short);
        $ciphertext = base64_decode($short);

        $key = md5($password . substr($iv, 0, 8), true);
        $result = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);

        if ($result === false) {
            throw new \RuntimeException('Decryption failed');
        }

        $privateKey = $this->derSerializer->parse($result);
        return new EncryptedPrivateKey($privateKey, $cipher, $iv);
    }
}
