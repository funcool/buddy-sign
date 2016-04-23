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

(ns buddy.sign.jws-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.keys :as keys]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.sign.jws :as jws]
            [buddy.sign.util :as util]))

(def secret "test")
(def rsa-privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret"))
(def rsa-pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))
(def ec-privkey (keys/private-key "test/_files/privkey.ecdsa.pem" "secret"))
(def ec-pubkey (keys/public-key "test/_files/pubkey.ecdsa.pem"))

(defn- unsign-exp-succ
  ([signed claims]
   (unsign-exp-succ signed claims {}))
  ([signed claims opts]
   (is (= (jws/unsign signed secret opts) claims))))

(defn- unsign-exp-fail
  ([signed cause]
   (unsign-exp-fail signed cause {}))
  ([signed cause opts]
   (try
     (jws/unsign signed secret opts)
     (throw (Exception. "unexpected"))
     (catch clojure.lang.ExceptionInfo e
       (is (= (:cause (ex-data e)) cause))))))

(deftest jws-decode
  (let [candidate {:foo "bar"}
        signed (jws/encode candidate secret)]
    (unsign-exp-succ signed candidate)))

(deftest jws-time-claims-validation
  (testing "current time claims validation"
    (let [candidate {:foo "bar"}
          now       (util/timestamp)
          claims    {:iat now :nbf now :exp (+ now 60)}
          signed    (jws/sign candidate secret claims)]
      (unsign-exp-succ signed (merge candidate claims))))

  (testing ":exp claim validation"
    (let [candidate {:foo "bar"}
          signed    (jws/encode candidate secret {:exp 10})]
      (unsign-exp-succ signed (assoc candidate :exp 10) {:now 0})
      (unsign-exp-succ signed (assoc candidate :exp 10) {:now 9})
      (unsign-exp-fail signed :exp {:now 10})
      (unsign-exp-fail signed :exp {:now 11}))

  (testing ":nbf claim validation"
    (let [candidate {:foo "bar"}
          signed    (jws/sign candidate secret {:nbf 10})]
      (unsign-exp-fail signed :nbf {:now 0})
      (unsign-exp-fail signed :nbf {:now 9})
      (unsign-exp-succ signed (assoc candidate :nbf 10) {:now 10})
      (unsign-exp-succ signed (assoc candidate :nbf 10) {:now 11})))))

(deftest jws-other-claims-validation
  (testing ":iss claim validation"
    (let [candidate {:foo "bar" :iss "foo:bar"}
          signed    (jws/sign candidate secret)]
      (unsign-exp-succ signed candidate)
      (unsign-exp-fail signed :iss {:iss "bar:foo"})))

  (testing ":aud claim validation"
    (let [candidate {:foo "bar" :aud "foo:bar"}
          signed    (jws/sign candidate secret)]
      (unsign-exp-succ signed candidate)
      (unsign-exp-fail signed :aud {:aud "bar:foo"}))))

(deftest jws-hs256-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate secret {:alg :hs256})
        result'   (jws/unsign result secret {:alg :hs256})]
    (is (= result' candidate))))

(deftest jws-hs512-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate secret {:alg :hs512})
        result'   (jws/unsign result secret {:alg :hs512})]
    (is (= result' candidate))))

(deftest jws-rs256-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate rsa-privkey {:alg :rs256})
        result'   (jws/unsign result rsa-pubkey {:alg :rs256})]
    (is (= result' candidate))))

(deftest jws-rs512-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate rsa-privkey {:alg :rs512})
        result'   (jws/unsign result rsa-pubkey {:alg :rs512})]
    (is (= result' candidate))))


(deftest jws-ps256-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate rsa-privkey {:alg :ps256})
        result'   (jws/unsign result rsa-pubkey {:alg :ps256})]
    (is (= result' candidate))))

(deftest jws-ps512-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate rsa-privkey {:alg :ps512})
        result'   (jws/unsign result rsa-pubkey {:alg :ps512})]
    (is (= result' candidate))))

(deftest jws-es256-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate ec-privkey {:alg :es256})
        result'   (jws/unsign result ec-pubkey {:alg :es256})]
    (is (= result' candidate))))

(deftest jws-es512-sign-unsign
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate ec-privkey {:alg :es512})
        result'   (jws/unsign result ec-pubkey {:alg :es512})]
    (is (= result' candidate))))

(deftest jws-wrong-key
  (let [candidate {:foo "bar"}
        result    (jws/sign candidate ec-privkey {:alg :es512})]
    (unsign-exp-fail result :header)))

(deftest wrong-data
  ;; (str "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9."
  ;;      "eyJmb28iOiJiYXIifQ."
  ;;      "FvlogSd-xDr6o2zKLNfNDbREbCf1TcQri3N7LkvRYDs")

  (unsign-exp-fail "xyz" :signature)
  (let [data (str "."
                  "eyJmb28iOiJiYXIifQ."
                  "FvlogSd-xDr6o2zKLNfNDbREbCf1TcQri3N7LkvRYDs")]
    (unsign-exp-fail data :signature))
  (let [data (str "eyJmb28iOiJiYXIifQ."
                  "FvlogSd-xDr6o2zKLNfNDbREbCf1TcQri3N7LkvRYDs")]
    (unsign-exp-fail data :signature)))
