;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.be>
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
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]
            [buddy.sign.jwe :as jwe]
            [buddy.sign.util :as util]
            [slingshot.slingshot :refer [try+]]))

(def secret (codecs/hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f")))

(deftest vectortests
  (let [secret (codecs/hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                                       "101112131415161718191a1b1c1d1e1f"))
        keymac (codecs/hex->bytes "000102030405060708090a0b0c0d0e0f")
        keyenc (codecs/hex->bytes "101112131415161718191a1b1c1d1e1f")

        iv (codecs/hex->bytes "1af38c2dc2b96ffdd86694092341bc04")
        aad (codecs/hex->bytes (str "546865207365636f6e64207072696e63"
                                    "69706c65206f66204175677573746520"
                                    "4b6572636b686f666673"))
        al (codecs/hex->bytes "0000000000000150")

        p (codecs/hex->bytes (str "41206369706865722073797374656d20"
                                  "6d757374206e6f742062652072657175"
                                  "6972656420746f206265207365637265"
                                  "742c20616e64206974206d7573742062"
                                  "652061626c6520746f2066616c6c2069"
                                  "6e746f207468652068616e6473206f66"
                                  "2074686520656e656d7920776974686f"
                                  "757420696e636f6e76656e69656e6365"))
        e (codecs/hex->bytes (str "c80edfa32ddf39d5ef00c0b468834279"
                                  "a2e46a1b8049f792f76bfe54b903a9c9"
                                  "a94ac9b47ad2655c5f10f9aef71427e2"
                                  "fc6f9b3f399a221489f16362c7032336"
                                  "09d45ac69864e3321cf82935ac4096c8"
                                  "6e133314c54019e8ca7980dfa4b9cf1b"
                                  "384c486f3a54c51078158ee5d79de59f"
                                  "bd34d848b3d69550a67646344427ade5"
                                  "4b8851ffb598f7f80074b9473c82e2db"))
        m (codecs/hex->bytes (str "652c3fa36b0a7c5b3219fab3a30bc1c4"
                                  "e6e54582476515f0ad9f75a2b71c73ef"))
        t (codecs/hex->bytes (str "652c3fa36b0a7c5b3219fab3a30bc1c4"))]

    ;; Test `extract-encryption-key`
    (let [function #'jwe/extract-encryption-key
          result (function secret :a128cbc-hs256)]
      (is (bytes/equals? result keyenc)))

    ;; Test `calculate-aad-length`
    (let [function #'jwe/calculate-aad-length
          result (function aad)]
      (is (bytes/equals? result al)))

    ;; Test `generate-ciphertext`
    (let [function #'jwe/aead-encrypt
          [ciphertext authtag] (function {:plaintext p
                                          :algorithm :a128cbc-hs256
                                          :secret secret
                                          :aad aad
                                          :iv iv})]
      (is (bytes/equals? ciphertext e))
      (is (bytes/equals? authtag t)))
))

(def data {:userid 1 :scope "auth"})
(def key16 (nonce/random-bytes 16))
(def key24 (nonce/random-bytes 24))
(def key32 (nonce/random-bytes 32))
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
          signed    (jwe/encrypt candidate secret {:exp exp})
          unsigned  (jwe/decrypt signed secret)]
      (is (= unsigned (assoc candidate :exp exp)))
      (Thread/sleep 3000)
      (try+
        (jwe/decrypt signed secret)
        (catch [:type :validation] {:keys [cause]}
          (is (= cause :exp))))))

  (testing ":nbf claim validation"
    (let [candidate {:foo "bar"}
          now       (util/timestamp)
          nbf       (+ now 2)
          signed    (jwe/encrypt candidate secret {:nbf nbf})
          unsigned  (jwe/decrypt signed secret)]
      (is (= unsigned (assoc candidate :nbf nbf)))
      (Thread/sleep 3000)
      (try+
        (jwe/decrypt signed secret)
        (catch [:type :validation] {:keys [cause]}
          (is (= cause :nbf))))))

  (testing ":iss claim validation"
    (let [candidate {:foo "bar" :iss "foo:bar"}
          result  (jwe/encrypt candidate secret)
          result' (jwe/decrypt result secret)]
      (is (= result' candidate))
      (try+
        (jwe/decrypt result secret {:iss "bar:foo"})
        (catch [:type :validation] {:keys [cause]}
          (is (= cause :iss))))))

  (testing ":aud claim validation"
    (let [candidate {:foo "bar" :aud "foo:bar"}
          result  (jwe/encrypt candidate secret)
          result' (jwe/decrypt result secret)]
      (is (= result' candidate))
      (try+
        (jwe/decrypt result secret {:aud "bar:foo"})
        (catch [:type :validation] {:keys [cause]}
          (is (= cause :aud))))))
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
      (try+
        (jwe/decrypt token key32 {:enc :a128cbc-hs256})
        (catch [:type :validation] {:keys [cause]}
          (is (= cause :authtag))))))
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
  (try+
   (jwe/decrypt "xyz" secret)
   (catch [:type :validation] {:keys [cause message]}
     (is (= cause :signature)))))
