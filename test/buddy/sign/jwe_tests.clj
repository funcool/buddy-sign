;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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

(defn- decrypt-exp-succ
  ([signed claims]
   (decrypt-exp-succ signed claims {}))
  ([signed claims opts]
   (is (= (jwe/decrypt signed secret opts) claims))))

(defn- decrypt-exp-fail
  ([signed cause]
   (decrypt-exp-fail signed cause {}))
  ([signed cause opts]
   (try
     (jwe/decrypt signed secret opts)
     (throw (Exception. "unexpected"))
     (catch clojure.lang.ExceptionInfo e
       (is (= (:cause (ex-data e)) cause))))))

(deftest jwe-time-claims-validation
  (testing "current time claims validation"
    (let [now (util/timestamp)
          candidate {:foo "bar" :iat now :nbf now :exp (+ now 60)}
          signed    (jwe/encrypt candidate secret)]
      (decrypt-exp-succ signed candidate)))

  (testing ":iat claim validation"
    (let [candidate {:foo "bar" :iat 10}
          signed    (jwe/encrypt candidate secret)]
      (decrypt-exp-fail signed :iat {:now 0})
      (decrypt-exp-fail signed :iat {:now 9})
      (decrypt-exp-succ signed candidate {:now 10})
      (decrypt-exp-succ signed candidate {:now 11})))

  (testing ":exp claim validation"
    (let [candidate {:foo "bar" :exp 10}
          signed    (jwe/encrypt candidate secret)]
      (decrypt-exp-succ signed candidate {:now 0})
      (decrypt-exp-succ signed candidate {:now 9})
      (decrypt-exp-fail signed :exp {:now 10})
      (decrypt-exp-fail signed :exp {:now 11})))

  (testing ":nbf claim validation"
    (let [candidate {:foo "bar" :nbf 10}
          signed    (jwe/encrypt candidate secret)]
      (decrypt-exp-fail signed :nbf {:now 0})
      (decrypt-exp-fail signed :nbf {:now 9})
      (decrypt-exp-succ signed candidate {:now 10})
      (decrypt-exp-succ signed candidate {:now 11}))))

(deftest jws-other-claims-validation
  (testing ":iss claim validation"
    (let [candidate {:foo "bar" :iss "foo:bar"}
          signed    (jwe/encrypt candidate secret)]
      (decrypt-exp-succ signed candidate)
      (decrypt-exp-fail signed :iss {:iss "bar:foo"})))

  (testing ":aud claim validation"
    (let [candidate {:foo "bar" :aud "foo:bar"}
          signed    (jwe/encrypt candidate secret)]
      (decrypt-exp-succ signed candidate)
      (decrypt-exp-fail signed :aud {:aud "bar:foo"}))))

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
