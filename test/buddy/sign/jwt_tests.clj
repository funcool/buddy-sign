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

(ns buddy.sign.jwt-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]
            [buddy.sign.util :as util]
            [cheshire.core :as json]))

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

(defn- unsign-exp-succ
  ([get-claims-fn signed claims]
   (unsign-exp-succ get-claims-fn signed claims {}))
  ([get-claims-fn signed claims opts]
   (is (= (get-claims-fn signed opts) claims))))

(defn- unsign-exp-fail
  ([get-claims-fn signed cause]
   (unsign-exp-fail get-claims-fn signed cause {}))
  ([get-claims-fn signed cause opts]
   (try
     (get-claims-fn signed opts)
     (is false "get-claims-fn should throw")
     (catch clojure.lang.ExceptionInfo e
       (is (= (:cause (ex-data e)) cause))))))

(deftest jwt-jws-decode
  (let [claims {:aud "buddy"}
        signed (jwt/sign claims secret {:alg :hs256})
        returned-claims (jwt/unsign signed secret {:alg :hs256})]
    (is (= returned-claims claims) "decoded claims must match up to original")))

(deftest jwt-jwe-decode
  (let [claims {:aud "buddy"}
        signed (jwt/encrypt claims key16 {:alg :dir :enc :a128gcm})
        returned-claims (jwt/decrypt signed key16 {:alg :dir :enc :a128gcm})]
    (is (= returned-claims claims) "decoded claims must match up to original")))

(deftest jwt-jws-encode
  (let [claims {:aud "buddy"}
        jwt (jwt/sign claims secret {:alg :hs256})]
    (testing "round trip"
      (let [returned-claims (jwt/unsign jwt secret {:alg :hs256})]
            (is (= returned-claims claims) "claims should match")))
    (testing "JWT typ in JOSE Header"
      (let [header (jws/decode-header jwt)]
        (is (= "JWT" (:typ header)) "typ header not found")))))

(deftest jwt-claims-validation
  (let [make-jwt-fn #(jwt/sign % secret {:alg :hs256})
        get-claims-fn #(jwt/unsign %1 secret (merge {:alg :hs256} %2))
        unsign-exp-succ (partial unsign-exp-succ get-claims-fn)
        unsign-exp-fail (partial unsign-exp-fail get-claims-fn)]

    (testing "current time claims validation"
      (let [now       (util/timestamp)
            candidate {:foo "bar" :iat now :nbf now :exp (+ now 60)}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-succ signed candidate)))

    (testing ":iat claim validation"
      (let [candidate {:foo "bar" :iat 10}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-fail signed :iat {:now 0})
        (unsign-exp-fail signed :iat {:now 9})
        (unsign-exp-succ signed candidate {:now 10})
        (unsign-exp-succ signed candidate {:now 11})))

    (testing ":exp claim validation"
      (let [candidate {:foo "bar" :exp 10}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-succ signed candidate {:now 0})
        (unsign-exp-succ signed candidate {:now 9})
        (unsign-exp-fail signed :exp {:now 10})
        (unsign-exp-fail signed :exp {:now 11})))

    (testing ":nbf claim validation"
      (let [candidate {:foo "bar" :nbf 10}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-fail signed :nbf {:now 0})
        (unsign-exp-fail signed :nbf {:now 9})
        (unsign-exp-succ signed candidate {:now 10})
        (unsign-exp-succ signed candidate {:now 11})))

    (testing ":iss claim validation"
      (let [candidate {:foo "bar" :iss "foo:bar"}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-succ signed candidate)
        (unsign-exp-fail signed :iss {:iss "bar:foo"})))

    (testing ":aud claim validation"
      (testing "single audience special case"
        (let [candidate {:foo "bar" :aud "foo:bar"}
              signed    (make-jwt-fn candidate)]
          (unsign-exp-succ signed candidate)
          (unsign-exp-fail signed :aud {:aud "bar:foo"})))

      (testing "multi-audience case"
        (let [audience  ["foo:bar" "bar:baz"]
              candidate {:foo "bar" :aud audience}
              signed    (make-jwt-fn candidate)]
          (doseq [aud audience]
            (unsign-exp-succ signed candidate {:aud aud}))
          (unsign-exp-fail signed :aud {:aud "bar:foo"}))))))

(deftest jwt-jwtio-example
  (let [jwt (str "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                 "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I"
                 "kpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA9"
                 "5OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
        claims (jwt/unsign jwt "secret" {:alg :hs256})]
    (is (= claims {:sub "1234567890"
                   :name "John Doe"
                   :admin true}) "jwt.io example")))

(deftest jwt-claims-must-be-map
  (is (thrown? AssertionError (jwt/sign "qwe" secret {:alg :hs256}))
      "claims should be a map"))

(deftest jwt-no-json-payload
  (let [jws (jws/sign "foobar" secret {:alg :hs256})]
    (try
      (jwt/unsign jws secret {:alg :hs256})
      (is false "unsign should throw")
      (catch clojure.lang.ExceptionInfo e
        (is (= (:cause (ex-data e)) :signature))))))
