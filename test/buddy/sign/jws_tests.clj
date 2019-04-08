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

(ns buddy.sign.jws-tests
  (:require [clojure.test :refer :all]
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
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
  ([signed candidate]
   (unsign-exp-succ signed candidate nil))
  ([signed candidate opts]
   (is (bytes/equals? (jws/unsign signed secret opts)
                      (codecs/to-bytes candidate)))))

(defn- unsign-exp-fail
  ([signed cause]
   (unsign-exp-fail signed cause nil))
  ([signed cause opts]
   (try
     (jws/unsign signed secret opts)
     (throw (Exception. "unexpected"))
     (catch clojure.lang.ExceptionInfo e
       (is (= cause (:cause (ex-data e))))))))

(deftest jws-wrong-key
  (let [candidate "foo bar "
        result    (jws/sign candidate ec-privkey {:alg :es512})]
    (unsign-exp-fail result :signature {:alg :hs256})))

(defspec jws-spec-alg-hs 500
  (props/for-all
   [key (gen/one-of [gen/bytes gen/string])
    data (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:hs512 :hs384 :hs256])]
   (let [res1 (jws/sign data key {:alg alg})
         res2 (jws/unsign res1 key {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))

(defspec jws-spec-alg-ps-and-rs 500
  (props/for-all
   [data (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:ps512 :ps384 :ps256 :rs512 :rs384 :rs256])]
   (let [res1 (jws/sign data rsa-privkey {:alg alg})
         res2 (jws/unsign res1 rsa-pubkey {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))

(defspec jws-spec-alg-ps-and-rs-from-header 500
   (props/for-all
    [data (gen/one-of [gen/bytes gen/string])
     alg (gen/elements [:ps512 :ps384 :ps256 :rs512 :rs384 :rs256])]
     (let [res1 (jws/sign data rsa-privkey {:alg alg})
           res2 (jws/unsign res1 rsa-pubkey)]
       (is (bytes/equals? res2 (codecs/to-bytes data))))))

(defspec jws-spec-custom-headers 500
  (props/for-all
   [data (gen/one-of [gen/bytes gen/string])
    nonce (gen/one-of [gen/string])
    alg (gen/elements [:ps512 :ps384 :ps256 :rs512 :rs384 :rs256])]
   (let [header-data {:url "https://example.com" :nonce nonce}
         res1 (jws/sign data rsa-privkey {:alg alg :header header-data})
         res2 (jws/unsign res1 rsa-pubkey {:alg alg})
         header (jws/decode-header res1)]
     (is (bytes/equals? res2 (codecs/to-bytes data)))
     (is (= header (merge header-data {:alg alg}))))))

(defspec jws-spec-alg-es 500
  (props/for-all
   [data (gen/one-of [gen/bytes gen/string])
    alg (gen/elements [:es512 :es384 :es256])]
   (let [res1 (jws/sign data ec-privkey {:alg alg})
         res2 (jws/unsign res1 ec-pubkey {:alg alg})]
     (is (bytes/equals? res2 (codecs/to-bytes data))))))

(defspec jwe-spec-wrong-data 500
  (props/for-all
   [data gen/string-ascii]
   (try
    (jws/unsign data secret)
    (throw (Exception. "unexpected"))
    (catch clojure.lang.ExceptionInfo e
      (let [cause (:cause (ex-data e))]
        (is (or (= cause :signature)
                (= cause :header))))))))

(defspec jwe-spec-wrong-token 500
  (props/for-all
   [data1 gen/string-alphanumeric
    data2 gen/string-alphanumeric
    data3 gen/string-alphanumeric]
   (let [data (str data1 "." data2 "." data3)]
     (try
       (jws/unsign data secret)
       (throw (Exception. "unexpected"))
       (catch clojure.lang.ExceptionInfo e
         (let [cause (:cause (ex-data e))]
           (is (or (= cause :signature)
                   (= cause :header)))))))))
