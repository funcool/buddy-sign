;; Copyright (c) 2014-2015 Andrey Antukh <niwi@niwi.nz>
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
            [buddy.core.mac :as mac]
            [buddy.core.dsa :as dsa]
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [cheshire.core :as json]))

(def ^{:doc "List of supported signing algorithms"
       :dynamic true}
  *signers-map* {:hs256 {:signer   #(mac/hash %1 {:alg :hmac+sha256 :key %2})
                         :verifier #(mac/verify %1 %2 {:alg :hmac+sha256 :key %3})}
                 :hs512 {:signer   #(mac/hash %1 %2 {:alg :hmac+sha512 :key %2})
                         :verifier #(mac/verify %1 %2 {:alg :hmac+sha512 :key %3})}
                 :rs256 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha256 :key %2})
                         :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha256 :key %3})}
                 :rs512 {:signer   #(dsa/sign %1 {:alg :rsassa-pkcs15+sha512 :key %2})
                         :verifier #(dsa/verify %1 %2 {:alg :rsassa-pkcs15+sha512 :key %3})}
                 :ps256 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha256 :key %2})
                         :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha256 :key %3})}
                 :ps512 {:signer   #(dsa/sign %1 {:alg :rsassa-pss+sha512 :key %2})
                         :verifier #(dsa/verify %1 %2 {:alg :rsassa-pss+sha512 :key %3})}
                 :es256 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha256 :key %2})
                         :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha256 :key %3 })}
                 :es512 {:signer   #(dsa/sign %1 {:alg :ecdsa+sha512 :key %2})
                         :verifier #(dsa/verify %1 %2 {:alg :ecdsa+sha512 :key %3})}})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn normalize-date-claims
  "Normalize date related claims and return transformed object."
  [data]
  (into {} (map (fn [[key val]]
                  (if (satisfies? util/ITimestamp val)
                    [key (util/to-timestamp val)]
                    [key val])) data)))

(defn normalize-nil-claims
  "Given a raw headers, try normalize it removing any
  key with null values."
  [data]
  (into {} (remove (comp nil? second) data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- encode-header
  "Encode jws header"
  [alg typ]
  (let [algorithm (.toUpperCase (name alg))
        type (.toUpperCase (name typ))]
    (-> {:alg algorithm :typ type}
        (json/generate-string)
        (codecs/str->bytes)
        (codecs/bytes->safebase64))))

(defn- encode-claims
  "Encode jws claims."
  [input opts]
  (let [additionalclaims (-> (select-keys opts [:exp :nbf :iat :iss :aud])
                             (normalize-nil-claims)
                             (normalize-date-claims))]
    (-> (normalize-date-claims input)
        (merge additionalclaims)
        (json/generate-string)
        (codecs/str->bytes)
        (codecs/bytes->safebase64))))

(defn- parse-header
  "Parse jws header."
  [^String headerdata {:keys [alg] :or {alg :hs256}}]
  (when (nil? alg)
    (throw (ex-info "Missing `alg` parameter."
                    {:type :validation :cause :header})))
  (let [header (-> (codecs/safebase64->str headerdata)
                   (json/parse-string true))]
    (when (not= alg (keyword (str/lower-case (:alg header))))
      (throw (ex-info "The `alg` param mismatch with header value."
                      {:type :validation :cause :header})))
    (merge {:alg alg} (dissoc header :alg))))

(defn- parse-claims
  "Parse jws claims"
  [^String claimsdata {:keys [max-age iss aud]}]
  (let [claims (-> claimsdata
                   (codecs/safebase64->bytes)
                   (codecs/bytes->str)
                   (json/parse-string true))
        now (util/timestamp)]
    (when (and iss (not= iss (:iss claims)))
      (throw (ex-info (str "Issuer does not match " iss)
                      {:type :validation :cause :iss})))
    (when (and aud (not= aud (:aud claims)))
      (throw (ex-info (str "Audience does not match " aud)
                      {:type :validation :cause :aud})))
    (when (and (:exp claims) (> now (:exp claims)))
      (throw (ex-info (format "Token is expired (%s)" (:exp claims))
                      {:type :validation :cause :exp})))
    (when (and (:nbf claims) (< now (:nbf claims)))
      (throw (ex-info (format "Token is not yet valid (%s)" (:nbf claims))
                      {:type :validation :cause :nbf})))
    (when (and (:iat claims) (number? max-age) (> (- now (:iat claims)) max-age))
      (throw (ex-info (format "Token is older than max-age (%s)" max-age)
                      {:type :validation :cause :max-age})))
    claims))

(defn- calculate-signature
  "Given the bunch of bytes, a private key and algorithm,
  return a calculated signature as byte array."
  [{:keys [key alg header claims]}]
  (let [signer (get-in *signers-map* [alg :signer])
        authdata (str/join "." [header claims])]
    (-> (signer authdata key)
        (codecs/bytes->safebase64))))

(defn- verify-signature
  "Given a bunch of bytes, a previously generated
  signature, the private key and algorithm, return
  signature matches or not."
  [{:keys [alg signature key header claims]}]
  (let [verifier (get-in *signers-map* [alg :verifier])
        authdata (str/join "." [header claims])]
    (verifier authdata signature key)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn sign
  "Sign arbitrary length string/byte array using
  json web token/signature."
  ;; The exp nbf and iat keys in the options are deprecated
  ;; and will be removed in the next version.
  [claims pkey & [{:keys [alg typ] :or {alg :hs256 typ :jws} :as opts}]]
  {:pre [(map? claims)]}
  (let [header (encode-header alg typ)
        claims (encode-claims claims opts)
        signature (calculate-signature {:key pkey
                                        :alg alg
                                        :header header
                                        :claims claims})]
    (str/join "." [header claims signature])))

(defn unsign
  "Given a signed message, verify it and return
  the decoded claims."
  ([input pkey] (unsign input pkey {}))
  ([input pkey opts]
   (try
     (let [[header claims signature] (str/split input #"\." 3)
           {:keys [alg]} (parse-header header opts)
           signature (codecs/safebase64->bytes signature)]
       (when-not (verify-signature {:key pkey :signature signature
                                    :alg alg :header header :claims claims})
         (throw (ex-info "Message seems corrupt or manipulated."
                         {:type :validation :cause :signature})))
       (parse-claims claims opts))
     (catch com.fasterxml.jackson.core.JsonParseException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature}))))))

(util/defalias encode sign)
(util/defalias decode unsign)
