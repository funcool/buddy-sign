# FAQ

## When I should use JWE and when JWS?

The main difference between JWS and JWE, is that JWE encrypts the claims with
an algorithm that uses a one time key. Both provides good security, but JWE also
provides privacy of the data.

If you only stores the userid or something similar, JWS is recommended, because
it has less overhead. But if you are storing in the token claims that require
privacy, JWE is the solution that should be used.

## ECDSA vs EdDSA ?

ECDSA algorithm has one very weak point - it requires cryptographically secure
random numbers not only for key generation but also for EVERY signature creation.

If attacker has two signatures for same data and can guess random number used
for their creation, then she can calculate private key (see PS3 ECDSA exploit
for example).

Ed25519 on the other hand is specifically designed to avoid this kind of errors,
it also has very good performance characteristics both for signing and verification,
see https://tools.ietf.org/html/rfc8032[RFC8032] for details

## How I can generate keypairs?

Example on how to generate one Elliptic Curve DSA keypair:

```bash
# Generating params file
openssl ecparam -name prime256v1 -out ecparams.pem

# Generate a private key from params file
openssl ecparam -in ecparams.pem -genkey -noout -out ecprivkey.pem

# Generate a public key from private key
openssl ec -in ecprivkey.pem -pubout -out ecpubkey.pem
```

Example on how to generate one RSA keypair:

```bash
# Generate aes256 encrypted private key
openssl genrsa -aes256 -out privkey.pem 2048

# Generate public key from previously created private key.
openssl rsa -pubout -in privkey.pem -out pubkey.pem
```
