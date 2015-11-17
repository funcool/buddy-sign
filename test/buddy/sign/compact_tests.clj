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

(deftest compact-sign-unsign
  (testing "Signing with compat implementation using :hs256."
    (let [data {:foo1 "bar1"}
          signed (compact/encode data secret)]
      (is (= data (compact/decode signed secret)))))

  (testing "Using :poly1305-aes mac algorithm"
    (let [data {:foo1 "bar1"}
          signed (compact/sign data secret {:alg :poly1305-aes})]
      (is (= data (compact/unsign signed secret {:alg :poly1305-aes})))))

  (testing "Using :rs256 digital signature"
    (let [candidate {:foo "bar"}
          result    (-> (compact/sign candidate rsa-privkey {:alg :rs256})
                        (compact/unsign rsa-pubkey {:alg :rs256}))]
      (is (= result candidate))))

  (testing "Using :ps512 digital signature"
    (let [candidate {:foo "bar"}
          result    (-> (compact/sign candidate rsa-privkey {:alg :ps512})
                        (compact/unsign rsa-pubkey {:alg :ps512}))]
      (is (= result candidate))))

  (testing "Using :ec512 digital signature"
    (let [candidate {:foo "bar"}
          result    (-> (compact/sign candidate ec-privkey {:alg :es512})
                        (compact/unsign ec-pubkey {:alg :es512}))]
      (is (= result candidate))))

  (testing "Using :hs256 with max-age"
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
  )
