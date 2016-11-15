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
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
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

(def data (codecs/to-bytes "test-data"))
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

(def rsa-algs
  [:rsa-oaep :rsa-oaep-256 :rsa1_5])

(def encs
  [:a128gcm :a192gcm :a256gcm :a128cbc-hs256
   :a192cbc-hs384 :a256cbc-hs512])

;; --- Tests

(deftest jwe-decode-header
  (let [candidate "foo bar"
        encrypted (jwe/encrypt candidate secret {:typ "FOO"})
        header (jwe/decode-header encrypted)]
    (is (= {:alg :dir, :enc :a128cbc-hs256, :typ "FOO", :zip false} header))))

(deftest jwe-wrong-date-specific-test
  (let [token (str "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.."
                   "zkV7_0---NDlvQYfpNDfqw.hECYr8zURDvz9hdjz6s-O0HNF2"
                   "MhgHgXjnQN6KuUcgE.eXYr6ybqAYcQkkkuGNcNKA")]
    (try
      (jwe/decrypt token key32 {:enc :a128cbc-hs256})
      (throw (Exception. "unexpected"))
      (catch clojure.lang.ExceptionInfo e
        (let [cause (:cause (ex-data e))]
          (is (= cause :authtag)))))))

(deftest wrong-key-for-enc
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a256gcm})))
  (is (thrown? AssertionError (jwe/encrypt data key48 {:enc :a256gcm})))
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a192gcm})))
  (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a192gcm})))
  (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a128gcm})))
  (is (thrown? AssertionError (jwe/encrypt data key48 {:enc :a128gcm})))
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a256cbc-hs512})))
  (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a256cbc-hs512})))
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a192cbc-hs384})))
  (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a192cbc-hs384})))
  (is (thrown? AssertionError (jwe/encrypt data key64 {:enc :a192cbc-hs384})))
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a128cbc-hs256})))
  (is (thrown? AssertionError (jwe/encrypt data key48 {:enc :a128cbc-hs256})))
  (is (thrown? AssertionError (jwe/encrypt data key32 {:enc :a128gcm :alg :a128kw})))
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a128gcm :alg :a192kw})))
  (is (thrown? AssertionError (jwe/encrypt data key16 {:enc :a128gcm :alg :a256kw})))
  )

(defspec jwe-spec-alg-dir-enc-a256gcm 500
  (props/for-all
   [zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key32 {:enc :a256gcm :alg :dir :zip zip})
         res2 (jwe/decrypt res1 key32 {:enc :a256gcm :alg :dir :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-dir-enc-a192gcm 500
  (props/for-all
   [zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key24 {:enc :a192gcm :alg :dir :zip zip})
         res2 (jwe/decrypt res1 key24 {:enc :a192gcm :alg :dir :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-dir-enc-a128gcm 500
  (props/for-all
   [zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key16 {:enc :a128gcm :alg :dir :zip zip})
         res2 (jwe/decrypt res1 key16 {:enc :a128gcm :alg :dir :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-dir-enc-a256cbc-hs512 500
  (props/for-all
   [zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key64 {:enc :a256cbc-hs512 :zip zip})
         res2 (jwe/decrypt res1 key64 {:enc :a256cbc-hs512 :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-dir-enc-a192cbc-hs384 500
  (props/for-all
   [zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key48 {:enc :a192cbc-hs384 :zip zip})
         res2 (jwe/decrypt res1 key48 {:enc :a192cbc-hs384 :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-dir-enc-a128cbc-hs256 500
  (props/for-all
   [zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key32 {:enc :a128cbc-hs256 :zip zip})
         res2 (jwe/decrypt res1 key32 {:enc :a128cbc-hs256 :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-wrong-data 500
  (props/for-all
   [data gen/string-ascii]
   (try
    (jwe/decrypt data secret)
    (throw (Exception. "unexpected"))
    (catch clojure.lang.ExceptionInfo e
      (let [cause (:cause (ex-data e))]
        (is (or (= cause :signature)
                (= cause :header))))))))

(defspec jwe-spec-wrong-token 500
  (props/for-all
   [data1 gen/string-alphanumeric
    data2 gen/string-alphanumeric
    data3 gen/string-alphanumeric
    data4 gen/string-alphanumeric
    data5 gen/string-alphanumeric]
   (let [data (str data1 "." data2 "." data3 "." data4 "." data5)]
     (try
       (jwe/decrypt data secret)
       (throw (Exception. "unexpected"))
       (catch clojure.lang.ExceptionInfo e
         (let [cause (:cause (ex-data e))]
           (is (or (= cause :signature)
                   (= cause :header)))))))))

;; (deftest jwe-spec-wrong-data
;;   (try
;;     (jwe/decrypt ">e31kI6Gr)u2#FGRtGOGeK6^GM:\\]OuUgR7Qwqs[`pUw^Ll~VC?V:ddTa%l@$&]/T%z<`[]6[" secret)
;;     (throw (Exception. "unexpected"))
;;     (catch clojure.lang.ExceptionInfo e
;;       (let [cause (:cause (ex-data e))]
;;         (is (or (= cause :signature)
;;                 (= cause :header)))))))

(defspec jwe-spec-alg-rsa 100
  (props/for-all
   [enc (gen/elements encs)
    alg (gen/elements rsa-algs)
    zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data rsa-pubkey {:enc enc :alg alg :zip zip})
         res2 (jwe/decrypt res1 rsa-privkey {:enc enc :alg alg :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-a128kw 500
  (props/for-all
   [enc (gen/elements encs)
    zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key16 {:enc enc :alg :a128kw :zip zip})
         res2 (jwe/decrypt res1 key16 {:enc enc :alg :a128kw :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-a192kw 500
  (props/for-all
   [enc (gen/elements encs)
    zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key24 {:enc enc :alg :a192kw :zip zip})
         res2 (jwe/decrypt res1 key24 {:enc enc :alg :a192kw :zip zip})]
     (is (bytes/equals? res2 data)))))

(defspec jwe-spec-alg-a256kw 500
  (props/for-all
   [enc (gen/elements encs)
    zip gen/boolean
    data gen/bytes]
   (let [res1 (jwe/encrypt data key32 {:enc enc :alg :a256kw :zip zip})
         res2 (jwe/decrypt res1 key32 {:enc enc :alg :a256kw :zip zip})]
     (is (bytes/equals? res2 data)))))
