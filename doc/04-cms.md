# CMS (Compact Message Signing)

CMS is a high influence by django's cryptographic library and json web
signature/encryption signing algorithm with focus on have a compact
representation. It's build on top of fantastic `ptaoussanis/nippy`
serialization library.

In order to use this you shall include the concrete `nippy` library because
**buddy-sign** does not have a hardcoded dependency to it:

```clojure
;; project.clj
[com.taoensso/nippy "2.15.3"]

;; deps.edn
com.taoensso/nippy {:mvn/version "2.15.3"}
```

In the same way as JWS, it support a great number of different signing
algorithms that can be used for sign your messages:

| Algorithm name     | Hash algorithms   | Keywords           | Priv/Pub Key? |
|--------------------|-------------------|--------------------|---------------|
| Elliptic Curve DSA | sha256, sha512    | `:es256`, `:es512` | Yes |
| RSASSA PSS         | sha256, sha512    | `:ps256`, `:ps512` | Yes |
| RSASSA PKCS1 v1_5  | sha256, sha512    | `:rs256`, `:rs512` | Yes |
| Poly1305           | aes, twofish, serpent | `:poly1305-aes`, `:poly1305-serpent`, `:poly1305-twofish` | No |
| HMAC               | sha256*, sha512   | `:hs256`, `:hs512` | No |

In difference with jwt, this implementation is not limited to hash-map
like objects, and you can sign any clojure valid type.

Let see an example:

```clojure
(require '[buddy.sign.compact :as cms])

(def data (cms/sign #{:foo :bar} "secret")

(cms/unsign data "secret")
;; => #{:foo :bar}
```

Then, you also will be able validate the signed message based in its age:

```clojure
(cm/unsign data "secret" {:max-age (* 15 60)})
;; => ExceptionInfo: "Token is older than 1427836475"
```

**NOTE:** Only `:max-age` validation is bundlind all other validation
are delegated to the user code.


