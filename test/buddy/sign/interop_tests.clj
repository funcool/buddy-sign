;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.sign.interop-tests
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]
            [buddy.sign.jwe :as jwe]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]
            [buddy.sign.util :as util]
            [cheshire.core :as json])
  (:import com.nimbusds.jose.JWEHeader
           com.nimbusds.jose.JWSHeader
           com.nimbusds.jose.JWEAlgorithm
           com.nimbusds.jose.JWSAlgorithm
           com.nimbusds.jose.EncryptionMethod
           com.nimbusds.jose.Payload
           com.nimbusds.jose.JWEObject
           com.nimbusds.jwt.EncryptedJWT
           com.nimbusds.jwt.SignedJWT
           com.nimbusds.jwt.JWTClaimsSet
           com.nimbusds.jwt.JWTClaimsSet$Builder
           com.nimbusds.jose.crypto.MACSigner
           com.nimbusds.jose.crypto.MACVerifier
           com.nimbusds.jose.crypto.DirectEncrypter
           com.nimbusds.jose.crypto.DirectDecrypter
           com.nimbusds.jose.crypto.ECDSAVerifier
           (javax.crypto KeyGenerator)
           (java.security.interfaces ECPublicKey ECPrivateKey)
           (java.security SecureRandom KeyPairGenerator)
           (java.security.spec ECGenParameterSpec)))

(def secret (codecs/hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f")))

(def data {:userid 1 :scope "auth"})
(def key16 (nonce/random-bytes 16))
(def key24 (nonce/random-bytes 24))
(def key32 (nonce/random-bytes 32))
(def key32' (nonce/random-bytes 32))
(def key48 (nonce/random-bytes 48))
(def key64 (nonce/random-bytes 64))
(def rsa-privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret"))
(def rsa-pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))
(def ec-privkey (keys/private-key "test/_files/privkey.ecdsa.pem" "secret"))
(def ec-pubkey (keys/public-key "test/_files/pubkey.ecdsa.pem"))

(deftest interoperability-test-1
  (let [header (JWEHeader. JWEAlgorithm/DIR EncryptionMethod/A128GCM)
        claimsbuilder (doto (JWTClaimsSet$Builder.)
                        (.claim "test1" "test"))
        claims (.build claimsbuilder)

        jwt (doto (EncryptedJWT. header claims)
              (.encrypt (DirectEncrypter. ^bytes key16)))

        result (.serialize jwt)]
    (let [data (jwt/decrypt result key16 {:alg :dir :enc :a128gcm})]
      (is (= data {:test1 "test"})))))

(deftest interoperability-test-2
  (let [^String token (jwt/encrypt {:test1 "test"} key16 {:alg :dir :enc :a128gcm})
        jwt (doto (EncryptedJWT/parse token)
              (.decrypt (DirectDecrypter. ^bytes key16)))]
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))

(deftest interoperability-test-3
  (let [header (JWEHeader. JWEAlgorithm/DIR EncryptionMethod/A128CBC_HS256)
        claimsbuilder (doto (JWTClaimsSet$Builder.)
                        (.claim "test1" "test"))
        claims (.build claimsbuilder)

        jwt (doto (EncryptedJWT. header claims)
              (.encrypt (DirectEncrypter. ^bytes key32)))

        result (.serialize jwt)]
    (let [data (jwt/decrypt result key32 {:alg :dir :enc :a128cbc-hs256})]
      (is (= data {:test1 "test"})))))

(deftest interoperability-test-4
  (let [^String token (jwt/encrypt {:test1 "test"} key32 {:alg :dir :enc :a128cbc-hs256})
        jwt (doto (EncryptedJWT/parse token)
              (.decrypt (DirectDecrypter. ^bytes key32)))]
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))

(deftest interoperability-test-5
  (let [header (JWSHeader. JWSAlgorithm/HS256)
        claimsbuilder (doto (JWTClaimsSet$Builder.)
                        (.claim "test1" "test"))
        claims (.build claimsbuilder)

        jwt (doto (SignedJWT. header claims)
              (.sign (MACSigner. ^bytes key32)))

        result (.serialize jwt)]
    (let [data (-> (jws/unsign result key32 {:alg :hs256})
                   (codecs/bytes->str)
                   (json/parse-string true))]
      (is (= data {:test1 "test"})))))

(deftest interoperability-test-6
  (let [^String token (jws/sign (json/generate-string {:test1 "test"}) key32 {:alg :hs256})
        jwt (SignedJWT/parse token)]
    (is (.verify jwt (MACVerifier. ^bytes key32)))
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))

(defn generate-ecdsa-pair [curvename]
  (let [kg (KeyPairGenerator/getInstance "EC" "BC")
        _ (.initialize kg (ECGenParameterSpec. curvename) (SecureRandom/getInstance "SHA1PRNG"))
        pair (.generateKeyPair kg)
        public (.getPublic pair)
        private (.getPrivate pair)]
    [public private]))

(deftest interoperability-test-es256
  (let [[^ECPublicKey public ^ECPrivateKey private] (generate-ecdsa-pair "P-256")
        ^String token (jws/sign (json/generate-string {:test1 "test"}) private {:alg :es256})
        jwt (SignedJWT/parse token)]
    (is (.verify jwt (ECDSAVerifier. public)))
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))

(deftest interoperability-test-es384
  (let [[^ECPublicKey public ^ECPrivateKey private] (generate-ecdsa-pair "P-384")
        ^String token (jws/sign (json/generate-string {:test1 "test"}) private {:alg :es384})
        jwt (SignedJWT/parse token)]
    (is (.verify jwt (ECDSAVerifier. public)))
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))

(deftest interoperability-test-es512
  (let [[^ECPublicKey public ^ECPrivateKey private] (generate-ecdsa-pair "P-521")
        ^String token (jws/sign (json/generate-string {:test1 "test"}) private {:alg :es512})
        jwt (SignedJWT/parse token)]
    (is (.verify jwt (ECDSAVerifier. public)))
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))
