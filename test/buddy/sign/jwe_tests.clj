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

(ns buddy.sign.jwe-tests
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]
            [buddy.sign.jwe :as jwe]
            [buddy.sign.util :as util]))

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

(deftest jwe-time-claims-validation
  (testing ":exp claim validation"
    (let [candidate {:foo "bar"}
          now       (util/timestamp)
          exp       (+ now 2)
          signed    (jwe/encode candidate secret {:exp exp})
          unsigned  (jwe/decode signed secret)]
      (is (= unsigned (assoc candidate :exp exp)))
      (Thread/sleep 3000)
      (try
        (jwe/decrypt signed secret)
        (throw (Exception. "unexpected"))
        (catch clojure.lang.ExceptionInfo e
          (let [cause (:cause (ex-data e))]
            (is (= cause :exp)))))))

  (testing ":nbf claim validation"
    (let [candidate {:foo "bar"}
          now       (util/timestamp)
          nbf       (+ now 2)
          signed    (jwe/encrypt candidate secret {:nbf nbf})
          unsigned  (jwe/decrypt signed secret)]
      (is (= unsigned (assoc candidate :nbf nbf)))
      (Thread/sleep 3000)
      (try
        (jwe/decrypt signed secret)
        (throw (Exception. "unexpected"))
        (catch clojure.lang.ExceptionInfo e
          (let [cause (:cause (ex-data e))]
            (is (= cause :nbf)))))))

  (testing ":iss claim validation"
    (let [candidate {:foo "bar" :iss "foo:bar"}
          result  (jwe/encrypt candidate secret)
          result' (jwe/decrypt result secret)]
      (is (= result' candidate))
      (try
        (jwe/decrypt result secret {:iss "bar:foo"})
        (throw (Exception. "unexpected"))
        (catch clojure.lang.ExceptionInfo e
          (let [cause (:cause (ex-data e))]
            (is (= cause :iss)))))))

  (testing ":aud claim validation"
    (let [candidate {:foo "bar" :aud "foo:bar"}
          result  (jwe/encrypt candidate secret)
          result' (jwe/decrypt result secret)]
      (is (= result' candidate))
      (try
        (jwe/decrypt result secret {:aud "bar:foo"})
        (throw (Exception. "unexpected"))
        (catch clojure.lang.ExceptionInfo e
          (let [cause (:cause (ex-data e))]
            (is (= cause :aud)))))))
  )

(deftest jwe-alg-dir-enc-a128-hs256
  (testing "Encrypt and decrypt"
    (let [result (jwe/encrypt data key32 {:enc :a128cbc-hs256})
          result' (jwe/decrypt result key32 {:enc :a128cbc-hs256})]
      (is (= result' data))))

  (testing "Wrong key"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a128cbc-hs256})))
    (is (thrown? AssertionError (jwe/encrypt data key48 {:enc :a128cbc-hs256}))))

  (testing "Wrong data"
    (let [token (str "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.."
                     "zkV7_0---NDlvQYfpNDfqw.hECYr8zURDvz9hdjz6s-O0HNF2"
                     "MhgHgXjnQN6KuUcgE.eXYr6ybqAYcQkkkuGNcNKA")]
      (try
        (jwe/decrypt token key32 {:enc :a128cbc-hs256})
        (throw (Exception. "unexpected"))
        (catch clojure.lang.ExceptionInfo e
          (let [cause (:cause (ex-data e))]
            (is (= cause :authtag)))))))
  )

(deftest jwe-alg-dir-enc-a192-hs384
  (testing "Encrypt and decrypt"
    (let [result (jwe/encrypt data key48 {:enc :a192cbc-hs384})
          result' (jwe/decrypt result key48 {:enc :a192cbc-hs384})]
      (is (= result' data))))

  (testing "Wrong key"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a192cbc-hs384})))
    (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a192cbc-hs384})))
    (is (thrown? AssertionError (jwe/encrypt data key64 {:enc :a192cbc-hs384}))))
  )

(deftest jwe-alg-dir-enc-a256-hs512
  (testing "Encrypt and decrypt"
    (let [result (jwe/encrypt data key64 {:enc :a256cbc-hs512})
          result' (jwe/decrypt result key64 {:enc :a256cbc-hs512})]
      (is (= result' data))))

  (testing "Wrong key"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a256cbc-hs512})))
    (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a256cbc-hs512}))))
  )

(deftest jwe-alg-dir-enc-a128gcm
  (testing "Encrypt and decrypt"
    (let [result (jwe/encrypt data key16 {:enc :a128gcm})
          result' (jwe/decrypt result key16 {:enc :a128gcm})]
      (is (= result' data))))

  (testing "Wrong key"
    (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a128gcm})))
    (is (thrown? AssertionError (jwe/encrypt data key48 {:enc :a128gcm}))))
  )

(deftest jwe-alg-dir-enc-a192gcm
  (testing "Encrypt and decrypt"
    (let [result (jwe/encrypt data key24 {:enc :a192gcm})
          result' (jwe/decrypt result key24 {:enc :a192gcm})]
      (is (= result' data))))

  (testing "Wrong key"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a192gcm})))
    (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a192gcm}))))
  )

(deftest jwe-alg-dir-enc-a256gcm
  (testing "Encrypt and decrypt"
    (let [result (jwe/encrypt data key32 {:enc :a256gcm})
          result' (jwe/decrypt result key32 {:enc :a256gcm})]
      (is (= result' data))))

  (testing "Wrong key"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a256gcm})))
    (is (thrown? AssertionError (jwe/encrypt data key48 {:enc :a256gcm}))))
  )

(def encs [:a128gcm :a192gcm :a256gcm :a128cbc-hs256 :a192cbc-hs384 :a256cbc-hs512])

(deftest jwe-alg-aes128kw-matrix
  (testing "Encrypt and decrypt."
    (doseq [enc encs]
      (let [result (jwe/encrypt data key16 {:enc enc :alg :a128kw})
            result' (jwe/decrypt result key16 {:enc enc :alg :a128kw})]
        (is (= result' data)))))

  (testing "Wrong key length for algorithm"
    (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a128gcm :alg :a128kw})))))

(deftest jwe-alg-aes192kw-matrix
  (testing "Encrypt and decrypt."
    (doseq [enc encs]
      (let [result (jwe/encrypt data key24 {:enc enc :alg :a192kw})
            result' (jwe/decrypt result key24 {:enc enc :alg :a192kw})]
        (is (= result' data)))))

  (testing "Wrong key length for algorithm"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a128gcm :alg :a192kw})))))

(deftest jwe-alg-aes256kw-matrix
  (testing "Encrypt and decrypt."
    (doseq [enc encs]
      (let [result (jwe/encrypt data key32 {:enc enc :alg :a256kw})
            result' (jwe/decrypt result key32 {:enc enc :alg :a256kw})]
        (is (= result' data)))))

  (testing "Wrong key length for algorithm"
    (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a128gcm :alg :a256kw})))))

(deftest jwe-alg-rsa-matrix
  (testing "Encrypt and decrypt."
    (doseq [alg [:rsa-oaep :rsa-oaep-256 :rsa1_5]
            enc encs]
      (let [result (jwe/encrypt data rsa-pubkey {:enc enc :alg alg})
            result' (jwe/decrypt result rsa-privkey {:enc enc :alg alg})]
        (is (= result' data))))))

(deftest wrong-data
  (try
    (jwe/decrypt "xyz" secret)
    (throw (Exception. "unexpected"))
    (catch clojure.lang.ExceptionInfo e
      (let [cause (:cause (ex-data e))]
        (is (= cause :signature))))))

(deftest wrong-key
  (let [data (jwe/encrypt {:data "foobar"} key32 {:enc :a256gcm :alg :a256kw})]
    (try
      (jwe/decrypt data key32' {:enc :a256gcm :alg :a256kw})
      (throw (Exception. "unexpected"))
      (catch clojure.lang.ExceptionInfo e
        (let [cause (:cause (ex-data e))]
          (is (= cause :signature)))))))


(import 'com.nimbusds.jose.JWEHeader
        'com.nimbusds.jose.JWEAlgorithm
        'com.nimbusds.jose.EncryptionMethod
        'com.nimbusds.jose.Payload
        'com.nimbusds.jose.JWEObject
        'com.nimbusds.jwt.EncryptedJWT
        'com.nimbusds.jwt.JWTClaimsSet
        'com.nimbusds.jwt.JWTClaimsSet$Builder
        'com.nimbusds.jose.crypto.DirectEncrypter
        'com.nimbusds.jose.crypto.DirectDecrypter)

;; (deftest regression-compatibility
;;   (let [header (JWEHeader. JWEAlgorithm/DIR EncryptionMethod/A128GCM)
;;         payload (Payload. "{}")
;;         jweobj (JWEObject. header, payload)
;;         _ (.encrypt jweobj (DirectEncrypter. key16))
;;         result (.serialize jweobj)]
;;     (println "numbus:" result))
;;   (let [result (jwe/encrypt {} key16 {:alg :dir :enc :a128gcm})]
;;     (println "buddy" result)))

(deftest interoperability-test-1
  (let [header (JWEHeader. JWEAlgorithm/DIR EncryptionMethod/A128GCM)
        claimsbuilder (doto (JWTClaimsSet$Builder.)
                        (.claim "test1" "test"))
        claims (.build claimsbuilder)

        jwt (doto (EncryptedJWT. header claims)
              (.encrypt (DirectEncrypter. key16)))

        result (.serialize jwt)]
    (let [data (jwe/decrypt result key16 {:alg :dir :enc :a128gcm})]
      (is (= data {:test1 "test"})))))


(deftest interoperability-test-2
  (let [header (JWEHeader. JWEAlgorithm/DIR EncryptionMethod/A128CBC_HS256)
        claimsbuilder (doto (JWTClaimsSet$Builder.)
                        (.claim "test1" "test"))
        claims (.build claimsbuilder)

        jwt (doto (EncryptedJWT. header claims)
              (.encrypt (DirectEncrypter. key32)))

        result (.serialize jwt)]
    (let [data (jwe/decrypt result key32 {:alg :dir :enc :a128cbc-hs256})]
      (is (= data {:test1 "test"})))))

(deftest interoperability-test-3
  (let [token (jwe/encrypt {:test1 "test"} key16 {:alg :dir :enc :a128gcm})
        jwt (doto (EncryptedJWT/parse token)
              (.decrypt (DirectDecrypter. key16)))]
    (is (= "test" (.. jwt getJWTClaimsSet (getClaim "test1"))))))
