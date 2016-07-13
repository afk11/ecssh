## EcSSH

This library contains some basic tools for working with elliptic curve SSH keys. 

Private keys's can be created using PHPECC, and serialized using it's DER/PEM 
private key serializer. There is also the EncryptedPrivateKeySerializer, used to 
create older SSH formatted keys. PKCS#8 encoding is on the wishlist. 

There is also an SshPublicKeySerializer, which encodes the curve/public key in the SSH format. 
This is the encoding used for authentication (authorized_keys, Github, etc).

https://tools.ietf.org/html/rfc5656

#### The PKCS8 code is not yet ready for use!