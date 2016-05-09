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
            [buddy.sign.util :as util]))

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
     (throw (Exception. "unexpected"))
     (catch clojure.lang.ExceptionInfo e
       (is (= (:cause (ex-data e)) cause))))))

(deftest jwt-jws-decode 
  (let [claims {:aud "buddy"}
        signed (jws/sign claims mac-secret {:alg :hs256 :typ "JWT"})
        returned-claims (jwt/get-claims-jws signed mac-secret {:alg :hs256})]
    (is (= returned-claims claims) "decoded claims must match up to original"))) 

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
  (test-claims-validation (fn [claims] (jws/sign claims mac-secret {:alg :hs256 :typ "JWT"}))
                          (fn [message opts] 
                            (jwt/get-claims-jws message mac-secret (merge {:alg :hs256} opts)))))
