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
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]
            [buddy.sign.util :as util]
            [cheshire.core :as json]))

(def mac-secret "mac-secret")

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
        signed (jwt/make-jws claims mac-secret {:alg :hs256})
        returned-claims (jwt/get-claims-jws signed mac-secret {:alg :hs256})]
    (is (= returned-claims claims) "decoded claims must match up to original"))) 

(deftest jwt-jws-encode
  (let [claims {:aud "buddy"}
        jwt (jwt/make-jws claims mac-secret {:alg :hs256})]
    (testing "round trip"
      (let [returned-claims (jwt/get-claims-jws jwt mac-secret {:alg :hs256})]
            (is (= returned-claims claims) "claims should match")))
    (testing "JWT typ in JOSE Header"
      (let [header (jws/decode-header jwt {:alg :hs256})]
        (is (= "JWT" (:typ header)) "typ header not found")))))


(defn test-claims-validation [make-jwt-fn get-claims-fn]
  (let [unsign-exp-succ (partial unsign-exp-succ get-claims-fn)
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
      (let [candidate {:foo "bar" :aud "foo:bar"}
            signed    (make-jwt-fn candidate)]
        (unsign-exp-succ signed candidate)
        (unsign-exp-fail signed :aud {:aud "bar:foo"})))))

(deftest jws-claims-validation
  (testing "claims validation for jws jwts"
    (test-claims-validation 
      (fn [claims] (jwt/make-jws claims mac-secret {:alg :hs256}))
      (fn [message opts] 
        (jwt/get-claims-jws message mac-secret (merge {:alg :hs256} opts))))))

(deftest jwt-io-example
  (let [jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        claims (jwt/get-claims-jws jwt "secret" {:alg :hs256})]
    (is (= claims {:sub "1234567890"
                   :name "John Doe"
                   :admin true}) "jwt.io example")))

(deftest claims-must-be-map
  (is (thrown? AssertionError (jwt/make-jws "qwe" mac-secret {:alg :hs256}))
      "claims should be a map"))

(deftest no-json-payload
  (let [jws (jws/sign "foobar" mac-secret {:alg :hs256})]
    (try
      (jwt/get-claims-jws jws mac-secret {:alg :hs256})
      (is false "get-claims-jws should throw")
      (catch clojure.lang.ExceptionInfo e
        (is (= (:cause (ex-data e)) :signature))))))


