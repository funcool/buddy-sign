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

(ns buddy.test-buddy-sign
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.keys :refer :all]
            [buddy.sign.compact :as compact]
            [buddy.sign.jws :as jws]
            [clj-time.coerce :as jodac]
            [clj-time.core :as jodat]
            [clojure.java.io :as io]
            [cats.monad.either :as either])
  (:import java.util.Arrays))

(def secret "test")

(deftest buddy-sign-jws
  (let [plainkey "secret"
        rsa-privkey (private-key "test/_files/privkey.3des.rsa.pem" "secret")
        rsa-pubkey  (public-key "test/_files/pubkey.3des.rsa.pem")
        ec-privkey  (private-key "test/_files/privkey.ecdsa.pem" "secret")
        ec-pubkey   (public-key "test/_files/pubkey.ecdsa.pem")]

    (testing "Pass exp as claim or parameter shoult return same result"
      (let [candidate1 {"iss" "joe" :exp 1300819380}
            candidate2 {"iss" "joe"}
            result1    (jws/encode candidate1 plainkey)
            result2    (jws/encode candidate2 plainkey {:exp 1300819380})]
        (is (= result1 result2))))

    (testing "Unsing simple jws"
      (let [candidate {:foo "bar"}
            result    (-> (jws/encode candidate plainkey)
                          (either/from-either)
                          (jws/decode plainkey))]
        (is (either/right? result))
        (is (= (either/from-either result) candidate))))

    (testing "Unsigning jws with exp"
      (let [candidate {:foo "bar"}
            now       (jws/to-timestamp (jodat/now))
            exp       (+ now 2)
            signed    (-> (jws/encode candidate plainkey {:exp exp})
                          (either/from-either))]
        (let [unsigned (-> (jws/decode signed plainkey)
                           (either/from-either))]
          (is (= unsigned (assoc candidate :exp exp))))

        (Thread/sleep 3000)

        (let [unsigned (jws/decode signed plainkey)]
          (is (either/left? unsigned)))))

    (testing "Unsigning jws with nbf"
      (let [candidate {:foo "bar"}
            now       (jws/to-timestamp (jodat/now))
            nbf       (+ now 2)
            signed    (-> (jws/encode candidate plainkey {:nbf nbf})
                          (either/from-either))]
        (let [unsigned (jws/decode signed plainkey)]
          (is (either/right? unsigned))
          (is (= (either/from-either unsigned) (assoc candidate :nbf nbf))))

        (Thread/sleep 3000)

        (let [unsigned (jws/decode signed plainkey)]
          (is (either/left? unsigned)))))

    (testing "Using :hs256 hmac with expired token."
      (let [secret (safebase64->bytes (str "KdnIJv7h5r--N2Na7XfS0EiHUKrZm_"
                                           "qucUbF6PmE6FOMrelLwzBOGEmI17Uqmaeu"))
            data (str "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL29yc"
                      "GhpZC10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw1NGNhZmM0YzJlMGU"
                      "5YzZiMTQ5ZDMwY2QiLCJhdWQiOiJIdTRxd3FRaU9nVHJCNlliT2NHTXBUQTdpN"
                      "jFSNVp1SCIsImV4cCI6MTQyMjYyNTA5MCwiaWF0IjoxNDIyNTg5MDkwfQ.3wKN"
                      "ZzgghjpsPBi5gDwv-RkbzvhG22Npcfyl8SUZriI")
            result (jws/decode data secret {:alg :hs256})]
        (is (either/left? result))))

    (testing "Using :rs256 digital signature"
      (let [candidate {:foo "bar"}
            result    (-> (jws/encode candidate rsa-privkey {:alg :rs256})
                          (either/from-either)
                          (jws/decode rsa-pubkey {:alg :rs256}))]
        (is (= (either/from-either result) candidate))))

    (testing "Using :ps512 digital signature"
      (let [candidate {:foo "bar"}
            result    (-> (jws/encode candidate rsa-privkey {:alg :ps512})
                          (either/from-either)
                          (jws/decode rsa-pubkey {:alg :ps512}))]
        (is (= (either/from-either result) candidate))))

    (testing "Using :ec512 digital signature"
      (let [candidate {:foo "bar"}
            result    (-> (jws/encode candidate ec-privkey {:alg :es512})
                          (either/from-either)
                          (jws/decode ec-pubkey {:alg :es512}))]
        (is (= (either/from-either result) candidate))))
))

(deftest buddy-sign-compact
  (testing "Signing with compat implementation."
    (let [data {:foo1 "bar1"}
          signed (compact/encode data secret)]
      (is (= (either/right data)
             (compact/decode @signed secret)))))
)

