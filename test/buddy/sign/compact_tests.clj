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

(ns buddy.sign.compact-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.keys :as keys]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.sign.compact :as compact]
            [buddy.sign.util :as util]
            [cats.monad.either :as either]
            [slingshot.slingshot :refer [try+]]))

(def secret "test")
(def rsa-privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret"))
(def rsa-pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))
(def ec-privkey (keys/private-key "test/_files/privkey.ecdsa.pem" "secret"))
(def ec-pubkey (keys/public-key "test/_files/pubkey.ecdsa.pem"))

(deftest compact-sign-unsign
  (testing "Signing with compat implementation using :hs256."
    (let [data {:foo1 "bar1"}
          signed (compact/encode data secret)]
      (is (= (either/right data)
             (compact/decode @signed secret)))))

  (testing "Using :poly1305-aes mac algorithm"
    (let [data {:foo1 "bar1"}
          signed (compact/encode data secret {:alg :poly1305-aes})]
      (is (= (either/right data)
             (compact/decode @signed secret {:alg :poly1305-aes})))))

  (testing "Using :rs256 digital signature"
    (let [candidate {:foo "bar"}
          result    (-> (compact/encode candidate rsa-privkey {:alg :rs256})
                        (either/from-either)
                        (compact/decode rsa-pubkey {:alg :rs256}))]
      (is (= (either/from-either result) candidate))))

    (testing "Using :ps512 digital signature"
      (let [candidate {:foo "bar"}
            result    (-> (compact/encode candidate rsa-privkey {:alg :ps512})
                          (either/from-either)
                          (compact/decode rsa-pubkey {:alg :ps512}))]
        (is (= (either/from-either result) candidate))))

  (testing "Using :ec512 digital signature"
    (let [candidate {:foo "bar"}
          result    (-> (compact/encode candidate ec-privkey {:alg :es512})
                        (either/from-either)
                        (compact/decode ec-pubkey {:alg :es512}))]
      (is (= (either/from-either result) candidate))))

  (testing "Using :hs256 with max-age"
    (let [candidate {:foo "bar"}
          encoded   (compact/encode candidate secret)
          decoded1  (compact/decode @encoded secret {:max-age 1})
          _         (Thread/sleep 2000)
          decoded2  (compact/decode @encoded secret {:max-age 1})]
      (is (either/right? decoded1))
      (is (= @decoded1 candidate))
      (is (either/left? decoded2))
      (is (= @decoded2 "Expired data"))))
)
