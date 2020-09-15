# JWE (Json Web Encryption)

JSON Web Encryption (JWE) is a encryption part of Json Web Token (JWT)
specification and represents a encrypted content using JavaScript
Object Notation (JSON) based data structures.

In same way as JWS, this is a low level primitive that allows create
fully encrypted messages of arbitrary data:

```clojure
(require '[buddy.sign.jws :as jws])
(require '[buddy.core.nonce :as nonce])
(require '[buddy.core.bytes :as bytes])

(def key32 (nonce/random-bytes 32))
(def data (nonce/random-bytes 1024))

(def message (jwt/encrypt data key32))
(bytes/equals? (jws/decrypt message key32) data)
;; => true
```

The supported algorightms are documented on the [jwt
document](01-jwt.md).

