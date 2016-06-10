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

(ns buddy.sign.compact-tests
  (:require [clojure.test :refer :all]
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.hash :as hash]
            [buddy.core.keys :as keys]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.sign.compact :as compact]
            [buddy.sign.util :as util]))

(def secret (hash/sha256 "secret"))
(def rsa-privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret"))
(def rsa-pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))
(def ec-privkey (keys/private-key "test/_files/privkey.ecdsa.pem" "secret"))
(def ec-pubkey (keys/public-key "test/_files/pubkey.ecdsa.pem"))

(def not-nan? (complement #(Double/isNaN %)))

(def map-gen
  (gen/map gen/keyword
           (gen/one-of [gen/string-alphanumeric
                        gen/symbol
                        gen/keyword
                        (gen/such-that not-nan? gen/double)
                        gen/int])))


(defspec compact-spec-alg-hs 50
  (props/for-all
   [key (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:hs512 :hs256])
    data map-gen]
   (let [res1 (compact/sign data key {:alg alg})
         res2 (compact/unsign res1 key {:alg alg})]
     (is (= res2 data)))))

(defspec compact-spec-alg-poly 50
  (props/for-all
   [alg (gen/elements [:poly1305-aes :poly1305-serpent :poly1305-twofish])
    data map-gen]
   (let [res1 (compact/sign data secret {:alg alg})
         res2 (compact/unsign res1 secret {:alg alg})]
     (is (= res2 data)))))

(defspec compact-spec-alg-rsa 50
  (props/for-all
   [alg (gen/elements [:rs256 :rs512 :ps512 :ps256])
    data map-gen]
   (let [res1 (compact/sign data rsa-privkey {:alg alg})
         res2 (compact/unsign res1 rsa-pubkey {:alg alg})]
     (is (= res2 data)))))

(defspec compact-spec-alg-ec 50
  (props/for-all
   [alg (gen/elements [:es512 :es256])
    data map-gen]
   (let [res1 (compact/sign data ec-privkey {:alg alg})
         res2 (compact/unsign res1 ec-pubkey {:alg alg})]
     (is (= res2 data)))))

(deftest compact-test-validation
  (let [candidate {:foo "bar"}
        signed    (compact/sign candidate secret)
        unsigned1 (compact/decode signed secret {:max-age 1})]
    (Thread/sleep 2000)
    (is (= unsigned1 candidate))
    (try
      (compact/decode signed secret {:max-age 1})
      (catch clojure.lang.ExceptionInfo e
        (let [data (ex-data e)]
          (is (= (:cause data) :max-age)))))))
