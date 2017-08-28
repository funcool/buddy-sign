;; Copyright (c) 2014-2016 Andrey Antukh <niwi@niwi.nz>
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

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-40
;; - https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40

(ns buddy.sign.jws
  "Json Web Signature implementation."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.mac :as mac]
            [buddy.core.dsa :as dsa]
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [cheshire.core :as json]))

(def +signers-map+
  "Supported algorithms."
  {:hs256 {:signer   #(mac/hash %1 {:alg :hmac+sha256 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha256 :key %3})}
   :hs384 {:signer   #(mac/hash %1 {:alg :hmac+sha384 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha384 :key %3})}
   :hs512 {:signer   #(mac/hash %1 {:alg :hmac+sha512 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha512 :key %3})}
   :rs256 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha256 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha256 :key %3})}
   :rs384 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha384 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha384 :key %3})}
   :rs512 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha512 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha512 :key %3})}
   :ps256 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha256 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha256 :key %3})}
   :ps384 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha384 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha384 :key %3})}
   :ps512 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha512 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha512 :key %3})}
   :es256 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha256 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha256 :key %3})}
   :es384 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha384 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha384 :key %3})}
   :es512 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha512 :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha512 :key %3})}})

;; --- Implementation

(defn- encode-header
  [header]
  (-> header
      (update :alg #(str/upper-case (name %)))
      (json/generate-string)
      (b64/encode true)
      (codecs/bytes->str)))

(defn- parse-header
  [^String data]
  (let [header (-> (b64/decode data)
                   (codecs/bytes->str)
                   (json/parse-string true))]
    (when-not (map? header)
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :header})))
    (update header :alg #(keyword (str/lower-case %)))))

(defn- encode-payload
  [input]
  (-> (b64/encode input true)
      (codecs/bytes->str)))

(defn- decode-payload
  [payload]
  (b64/decode payload))

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array."
  [{:keys [key alg header payload]}]
  (let [signer (get-in +signers-map+ [alg :signer])
        authdata (str/join "." [header payload])]
    (-> (signer authdata key)
        (b64/encode true)
        (codecs/bytes->str))))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not."
  [{:keys [alg signature key header payload]}]
  (let [verifier (get-in +signers-map+ [alg :verifier])
        authdata (str/join "." [header payload])
        signature (b64/decode signature)]
    (verifier authdata signature key)))

(defn- split-jws-message
  [message]
  (str/split message #"\." 3))

;; --- Public Api

(defn decode-header
  "Given a message, decode the header.
  WARNING: This does not perform any signature validation."
  [input]
  (try
    (let [[header] (split-jws-message input)]
      (parse-header header))
    (catch com.fasterxml.jackson.core.JsonParseException e
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :header})))))

(defn sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [payload pkey & [{:keys [alg header] :or {alg :hs256} :as opts}]]
  {:pre [payload]}
  (let [header (-> (merge {:alg alg} header)
                   (encode-header))
        payload (encode-payload payload)
        signature (calculate-signature {:key pkey
                                        :alg alg
                                        :header header
                                        :payload payload})]
    (str/join "." [header payload signature])))

(defn unsign
  "Given a signed message, verify it and return
  the decoded payload."
  ([input pkey] (unsign input pkey nil))
  ([input pkey {:keys [alg] :or {alg :hs256}}]
   (let [[header payload signature] (split-jws-message input)]
     (when-not (verify-signature {:key pkey
                                  :signature signature
                                  :alg alg
                                  :header header
                                  :payload payload})
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature})))
     (decode-payload payload))))

(util/defalias encode sign)
(util/defalias decode unsign)
