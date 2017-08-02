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
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
            [buddy.core.codecs :as codecs]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]
            [buddy.core.bytes :as bytes]
            [buddy.sign.jwe :as jwe]
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

(defspec jwt-spec-encode-decode-jws 100
  (props/for-all
   [key (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:hs512 :hs256])
    data (gen/map (gen/resize 4 gen/keyword)
                  (gen/one-of [gen/string-alphanumeric gen/int]))]
   (let [res1 (jwt/sign data key {:alg alg})
         res2 (jwt/unsign res1 key {:alg alg})]
     (is (= res2 data)))))

(defspec jwt-spec-encode-decode-jwe 100
  (props/for-all
   [enc (gen/elements [:a128gcm :a192gcm :a256gcm :a128cbc-hs256
                       :a192cbc-hs384 :a256cbc-hs512])
    zip gen/boolean
    data (gen/map (gen/resize 4 gen/keyword)
                  (gen/one-of [gen/string-alphanumeric gen/int]))]
   (let [res1 (jwt/encrypt data key16 {:alg :a128kw :enc enc :zip zip})
         res2 (jwt/decrypt res1 key16 {:alg :a128kw :enc enc :zip zip})]
     (is (= res2 data)))))

(defspec jwt-spec-jwt-typ-on-header 100
  (props/for-all
   [data (gen/map (gen/resize 4 gen/keyword)
                  (gen/one-of [gen/string-alphanumeric gen/int]))]
   (let [res1 (jwt/encrypt data key16 {:alg :a128kw :enc :a128gcm :zip true})
         res2 (jwt/sign data key16 {:alg :hs256})
         hdr1 (jwe/decode-header res1)
         hdr2 (jws/decode-header res2)]
     (is (= "JWT" (:typ hdr1)) "typ header not found")
     (is (= "JWT" (:typ hdr2)) "typ header not found"))))

(defn jwt-claims-validation
  [make-jwt-fn get-claims-fn]
  (let [unsign-exp-succ (partial unsign-exp-succ get-claims-fn)
        unsign-exp-fail (partial unsign-exp-fail get-claims-fn)]

    (testing "current time claims validation"
      (let [now       (util/timestamp)
            candidate {:foo "bar" :iat now :nbf now :exp (+ now 60)}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-succ signed candidate)))

    (testing ":exp claim validation"
      (let [candidate {:foo "bar" :exp 10}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-succ signed candidate {:now 0})
        (unsign-exp-succ signed candidate {:now 9})
        (unsign-exp-succ signed candidate {:now 10 :leeway 1})
        (unsign-exp-fail signed :exp {:now 10})
        (unsign-exp-fail signed :exp {:now 11})
        (unsign-exp-fail signed :exp {:now 12 :leeway 1})))

    (testing ":nbf claim validation"
      (let [candidate {:foo "bar" :nbf 10}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-fail signed :nbf {:now 0})
        (unsign-exp-fail signed :nbf {:now 8 :leeway 1})
        (unsign-exp-fail signed :nbf {:now 9})
        (unsign-exp-succ signed candidate {:now 9 :leeway 1})
        (unsign-exp-succ signed candidate {:now 10})
        (unsign-exp-succ signed candidate {:now 11})))

    (testing ":iss claim validation"
      (testing "single issuer special case"
        (let [candidate {:foo "bar" :iss "foo:bar"}
              signed    (make-jwt-fn candidate)]
          (unsign-exp-succ signed candidate)
          (unsign-exp-fail signed :iss {:iss "bar:foo"})))

      (testing "multi-issuers case"
        (let [issuers   ["foo:bar" "bar:baz"]
              candidate {:foo "bar" :iss "foo:bar"}
              signed    (make-jwt-fn candidate)]
          (unsign-exp-succ signed candidate {:iss issuers})
          (unsign-exp-fail signed :iss {:iss ["bar:foo" "baz:bar"]}))))

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

(deftest jwt-jws-claims-validation
  (jwt-claims-validation
    #(jwt/sign % secret {:alg :hs256})
    #(jwt/unsign %1 secret (merge {:alg :hs256} %2))))

(deftest jwt-jwe-claims-validation
  (jwt-claims-validation
    #(jwt/encrypt % key16 {:alg :a128kw :enc :a128gcm})
    #(jwt/decrypt %1 key16 (merge {:alg :a128kw :enc :a128gcm} %2))))

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
