;; Copyright (c) Andrey Antukh <niwi@niwi.nz>
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
  "Json Web Signature implementation"
  (:require
   [buddy.core.codecs :as bc]
   [buddy.core.dsa :as dsa]
   [buddy.core.mac :as mac]
   [buddy.sign.util :as util]
   [buddy.util.ecdsa :refer [transcode-to-der transcode-to-concat]]
   [cheshire.core :as json]
   [clojure.string :as str]))

(def +signers-map+
  "Supported algorithms"
  {:hs256 {:signer   #(mac/hash %1 {:alg :hmac+sha256 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha256 :key %3})}
   :hs384 {:signer   #(mac/hash %1 {:alg :hmac+sha384 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha384 :key %3})}
   :hs512 {:signer   #(mac/hash %1 {:alg :hmac+sha512 :key %2})
           :verifier #(mac/verify %1 %2 {:alg :hmac+sha512 :key %3})}

   ;; NOT RECOMMENDED
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

   ;; ECDSA with signature conversions
   :es256 {:signer   #(-> (dsa/sign %1 {:alg :ecdsa+sha256 :key %2})
                          (transcode-to-concat 64))
           :verifier #(dsa/verify %1 (transcode-to-der %2) {:alg :ecdsa+sha256 :key %3})}
   :es384 {:signer   #(-> (dsa/sign %1 {:alg :ecdsa+sha384 :key %2})
                          (transcode-to-concat 96))
           :verifier #(dsa/verify %1 (transcode-to-der %2) {:alg :ecdsa+sha384 :key %3})}
   :es512 {:signer   #(-> (dsa/sign %1 {:alg :ecdsa+sha512 :key %2})
                          (transcode-to-concat 132))
           :verifier #(dsa/verify %1 (transcode-to-der %2) {:alg :ecdsa+sha512 :key %3})}

   :eddsa {:signer   #(dsa/sign %1 {:alg :eddsa :key %2})
           :verifier #(dsa/verify %1 %2 {:alg :eddsa :key %3})}})

;; --- Implementation

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array"
  [{:keys [key alg header payload]}]
  (let [signer   (get-in +signers-map+ [alg :signer])
        authdata (str header "." payload)]
    (-> (signer authdata key)
        (bc/bytes->b64 true)
        (bc/bytes->str))))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not"
  [{:keys [alg signature key header payload]}]
  (try
    (let [verifier  (get-in +signers-map+ [alg :verifier])
          authdata  (str header "." payload)
          signature (-> signature
                        (bc/str->bytes)
                        (bc/b64->bytes true))]
      (verifier authdata signature key))

    (catch java.lang.IllegalArgumentException e
      (throw (ex-info "Message seems corrupt or manipulated"
                      {:type :validation :cause :signature}
                      e)))
    (catch java.security.SignatureException e
      (throw (ex-info "Message seems corrupt or manipulated"
                      {:type :validation :cause :signature}
                      e)))))

;; --- Public Api

(defn decode-header
  "Given a message, decode the header

  WARNING: This does not perform any signature validation"
  [input]
  (let [[header] (str/split input #"\." 2)]
    (util/parse-jose-header header)))

(defn sign
  "Sign arbitrary length string/byte array using json web
  token/signature"
  ([payload pkey] (sign payload pkey nil))
  ([payload pkey {:keys [alg header] :or {alg :hs256} :as opts}]
   (assert (some? payload) "expected payload to be provided")
   (assert (some? pkey) "expected pkey to be provided")
   (let [header    (-> (into {:alg alg} header)
                       (util/encode-jose-header)
                       (bc/bytes->str))
         payload   (-> (bc/->bytes payload)
                       (bc/bytes->b64 true)
                       (bc/bytes->str))
         signature (calculate-signature {:key pkey
                                         :alg alg
                                         :header header
                                         :payload payload})]
     (str header "." payload "." signature))))

(defn unsign
  "Given a signed message, verify it and return the decoded payload"
  ([input pkey] (unsign input pkey nil))
  ([input pkey {:keys [alg] :or {alg :hs256}}]
   (let [[header payload signature] (some-> input (str/split #"\." 3))]
     (when (or (nil? header) (nil? payload) (nil? signature))
       (throw (ex-info "Message seems corrupt or manipulated"
                       {:type :validation :cause :signature})))
     (let [header-data (util/parse-jose-header header)
           params      {:key       (util/resolve-key pkey header-data)
                        :signature signature
                        :alg       alg
                        :header    header
                        :payload   payload}]
       (when-not (verify-signature params)
         (throw (ex-info "Message seems corrupt or manipulated"
                         {:type :validation :cause :signature})))

       (-> payload
           (bc/str->bytes)
           (bc/b64->bytes true))))))

(util/defalias encode sign)
(util/defalias decode unsign)
