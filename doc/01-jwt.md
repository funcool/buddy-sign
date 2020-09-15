# JWT (Json Web Token)

JSON Web Token (JWT) is a compact claims representation format
intended for space constrained environments such as HTTP Authorization
headers and URI query parameters.  JWTs encode claims to be
transmitted as a JavaScript Object Notation (JSON) object that is used
as the payload of a JSON Web Signature (JWS) structure or as the
plaintext of a JSON Web Encryption (JWE) structure, enabling the
claims to be digitally signed or MACed and/or encrypted.


## Supported algorithms

Here a table of supported algorithms for signing JWT claims using JWS
(Json Web Signature):

|Algorithm name     | Hash algorithms   | Keywords           | Priv/Pub Key? |
|---|---|---|---|
|Elliptic Curve DSA | sha256, sha512    | `:es256`, `:es512` | Yes |
|Edwards Curve DSA  | sha512            | `:eddsa`           | Yes |
|RSASSA PSS         | sha256, sha512    | `:ps256`, `:ps512` | Yes |
|RSASSA PKCS1 v1_5  | sha256, sha512    | `:rs256`, `:rs512` | Yes |
|HMAC               | sha256*, sha512   | `:hs256`, `:hs512` | No |

The JWE (Json Web Encryption) in difference to JWS uses two types of
algoritms: key encryption algorithms and content encryption
algorithms.

The *key encryption algorithms* are responsible of encrypt the key
that will be used for encrypt the content. This is a table that
exposes the currently supported _Key Encryption Algorithms_ (specified
in JWA RFC):

| Algorithm name | Decription | Keyword       | Shared Key Size |
|----------------|------------|---------------|-----------------|
| DIR            | Direct use of a shared symmetric key | `:dir` | (depends on content encryption algorithm) |
| A128KW         | AES128 Key Wrap | `:a128kw` | 16 bytes |
| A192KW         | AES192 Key Wrap | `:a192kw` | 24 bytes |
| A256KW         | AES256 Key Wrap | `:a256kw` | 32 bytes |
| RSA1_5         | RSA PKCS1 V1_5  | `:rsa1_5` | Asymetric key pair |
| RSA-OAEP       | RSA OAEP with SHA1 | `:rsa-oaep` | Asymetric key pair |
| RSA-OAEP-256   | RSA OAEP with SHA256 | `:rsa-oaep-256` | Asymetric key pair |


The *content encryption algoritms* are responsible of encrypt the
content. This is a table that exposes the currently supported _Content
Encryption Algorithms_ (all specified in the JWA RFC):

| Algorithm name | Description | Keyword | Shared Key Size |
|----------------|-------------|---------|-----------------|
| A128CBC-HS256  | AES128 with CBC mode and HMAC-SHA256  | `:a128cbc-hs256` | 32 bytes |
| A192CBC-HS384  | AES192 with CBC mode and HMAC-SHA384  | `:a192cbc-hs384` | 48 bytes |
| A256CBC-HS512  | AES256 with CBC mode and HMAC-SHA512  | `:a256cbc-hs512` | 64 bytes |
| A128GCM        | AES128 with GCM mode | `:a128gcm`    | 16 bytes |
| A192GCM        | AES192 with GCM mode | `:a192gcm`    | 24 bytes |
| A256GCM        | AES256 with GCM mode | `:a256gcm`    | 32 bytes |


## Signing data

Let start with signing data. For it we will use the `sign` function
from `buddy.sign.jws` namespace, and the `hs256` algorithm for
signining:

```clojure
(require '[buddy.sign.jwt :as jwt])

(jwt/sign {:userid 1} "secret")
;; "eyJ0eXAiOiJKV1MiLCJhbGciOiJIU..."
```

The `sign` function return a encoded and signed token as plain
`String` instance or an exception in case of something goes wrong. As
you can observe, no algorithm is passed as parameter. In this
situations the default one will be used, and in this case is `:hs256`.

**NOTE**: Due to the nature of the storage format, the input is
restricted mainly to json objects in the current version.


## Unsigning data

It's time to unsign data. That process consists on verify the
signature of incoming data and return the plain data (without
signature). For it we will use the `unsign` function from
`buddy.sign.jwt` namespace:

```clojure
(jwt/unsign data "secret")
;; => {:userid 1}
```

## Claims validation

_buddy-sign_ JWT implements validation of a concrete subset of claims:
*iat* (issue time), *exp* (expiration time), *nbf* (not before), *iss*
(issuer) and *aud* (audience).

The validation is performed on decoding the token. If `:exp` claim is
found and is posterior to the current date time (UTC) an validation
exception will be raised.  Alternatively, the time to validate token
against can be specified as `:now` option to `unsign`.

Additionaly, if you want to provide some leeway for the claims
validation, you can pass the `:leeway` option to the `unsign`
function.

Let see an example using direct api:

```clojure
(require '[clj-time.core :as time])

;; Define claims with `:exp` key
(def claims
  {:user 1 :exp (time/plus (time/now) (time/seconds 5))})

;; Serialize and sign a token with previously defined claims
(def token (jwt/sign claims "key"))

;; wait 5 seconds and try unsign it

(jwt/unsign token "key")
;; => ExceptionInfo "Token is older than :exp (1427836475)"

;; use timestamp in the past
(jwt/unsign token "key" {:now (time/minus (time/now) (time/seconds 5))})
;; => {:user 1}
```

## Encrypting data

Let start with encrypting data. For it we will use the `encrypt`
function from the `buddy.sign.jwt` namespace:

```clojure
(require '[buddy.sign.jwt :as jwt])
(require '[buddy.core.hash :as hash])

;; Hash your secret key with sha256 for
;; create a byte array of 32 bytes because
;; is a requirement for default content
;; encryption algorithm

(def secret (hash/sha256 "mysecret"))

;; Encrypt it using the previously
;; hashed key

(jwt/encrypt {:userid 1} secret {:alg :dir :enc :a128cbc-hs256})
;; "eyJ0eXAiOiJKV1MiLCJhbGciOiJIU..."
```

The `encrypt` function, like `sign` from *JWT*, returns a plain string
with encrypted and encoded content using a provided algorithm and
shared secret key.


## Decrypting Data

The decrypt is a inverse process, that takes encrypted data and the
shared key, and returns the plain data. For it, _buddy-sign_ exposes
the `decrypt` function.  Let see how you can use it:

```clojure
(jwt/decrypt incoming-data secret)
;; => {:userid 1}
```

## Digital signature algorithms

In order to use any of digital signature algorithms you must have a private/public
key. If you don't have one, don't worry, it is very easy to generate it using
*openssl* ([look on FAQ](./05-faq.md)).

Having generated a key pair, you can sign your messages using one of
supported digital signature algorithms.

Example of signing a string using _es256_ (eliptic curve dsa) algorithm:

```clojure
(require '[buddy.core.keys :as keys])

;; Create keys instances
(def ec-privkey (keys/private-key "ecprivkey.pem"))
(def ec-pubkey (keys/public-key "ecpubkey.pem"))

;; Use them like plain secret password with hmac algorithms for sign
(def signed-data (jwt/sign {:foo "bar"} ec-privkey {:alg :es256}))

;; And unsign
(def unsigned-data (jwt/unsign signed-data ec-pubkey {:alg :es256}))
```

## Asymetric encryption

In order to use any asymetric encryption algorithm, you should have
private/public key pair. If you don't have one, don't worry, it is
very easy to generate it using *openssl* ([look on FAQ](./05-faq.md)).

Then, having ready the key pair, you can strart using one of the supported
key encryption algorithm in the JWE specification such as `:rsa1_5`, `:rsa-oaep`
or `:rsa-oaep-256`.

Let see an demonstration example:


```clojure
(require '[buddy.core.keys :as keys])

;; Create keys instances
(def privkey (keys/private-key "privkey.pem"))
(def pubkey (keys/public-key "pubkey.pem"))

;; Encrypt data
(def encrypted-data (jwt/encrypt {:foo "bar"} pubkey
                                 {:alg :rsa-oaep
                                  :enc :a128cbc-hs256})

;; Decrypted
(def decrypted-data (jwt/decrypt encrypted-data privkey
                                 {:alg :rsa-oaep
                                  :enc :a128cbc-hs256}))
```
