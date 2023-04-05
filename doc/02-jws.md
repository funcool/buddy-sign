# JWS (Json Web Signature)

JSON Web Signature (JWS) is a signing part of Json Web Token (JWT)
specification and represents content secured with digital signatures
or Message Authentication Codes (MACs) using JavaScript Object
Notation (JSON) as serialization format.

In difference to JWT, this is more lowlevel signing primitive and
allows signing arbitrary binary data (instead of json formated
claims):

```clojure
(require '[buddy.sign.jws :as jws])
(require '[buddy.core.nonce :as nonce])
(require '[buddy.core.bytes :as bytes])

(def data (nonce/random-bytes 1024))
(def message (jws/sign data "secret"))

(bytes/equals? (jws/unsign message "secret") data)
;; => true
```

The supported algorithms are documented on the [jwt
document](01-jwt.md).
