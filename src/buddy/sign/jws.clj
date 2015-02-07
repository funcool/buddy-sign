;; Copyright (c) 2014 Andrey Antukh <niwi@niwi.be>
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
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.sign.rsapss :as rsapss]
            [buddy.core.sign.rsapkcs15 :as rsapkcs]
            [buddy.core.sign.ecdsa :as ecdsa]
            [buddy.core.util :refer [maybe-let]]
            [clj-time.coerce :as jodac]
            [clj-time.core :as jodat]
            [clojure.string :as str]
            [cheshire.core :as json]
            [cats.monad.either :as either])
  (:import clojure.lang.Keyword))

(def ^{:doc "List of supported signing algorithms"
       :dynamic true}
  *signers-map* {:hs256 {:signer   #(hmac/hmac %1 %2 :sha256)
                         :verifier #(hmac/verify %1 %2 %3 :sha256)}
                 :hs512 {:signer   #(hmac/hmac %1 %2 :sha512)
                         :verifier #(hmac/verify %1 %2 %3 :sha512)}
                 :rs256 {:signer   #(rsapkcs/rsapkcs15 %1 %2 :sha256)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha256)}
                 :rs512 {:signer   #(rsapkcs/rsapkcs15 %1 %2 :sha512)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha512)}
                 :ps256 {:signer   #(rsapss/rsapss %1 %2 :sha256)
                         :verifier #(rsapss/verify %1 %2 %3 :sha256)}
                 :ps512 {:signer   #(rsapss/rsapss %1 %2 :sha512)
                         :verifier #(rsapss/verify %1 %2 %3 :sha512)}
                 :es256 {:signer   #(ecdsa/ecdsa %1 %2 :sha256)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha256)}
                 :es512 {:signer   #(ecdsa/ecdsa %1 %2 :sha512)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha512)}})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Utils protocols related to time checking
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol ITimestamp
  "Default protocol for convert any tipe to
  unix timestamp with default implementation for
  java.util.Date"
  (to-timestamp [obj] "Covert to timestamp"))

(extend-protocol ITimestamp
  java.util.Date
  (to-timestamp [obj]
    (quot (jodac/to-long obj) 1000))

  org.joda.time.DateTime
  (to-timestamp [obj]
    (quot (jodac/to-long obj) 1000)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- normalize-date-claims
  "Normalize date related claims and return transformed object."
  [data]
  (into {} (map (fn [[key val]]
                  (if (satisfies? ITimestamp val)
                    [key (to-timestamp val)]
                    [key val])) data)))

(defn- normalize-nil-claims
  "Given a raw headers, try normalize it removing any
  key with null values and convert Dates to timestamps."
  [data]
  (into {} (remove (comp nil? second) data)))

(defn- encode-header
  "Encode jws header"
  [alg extra]
  (let [algorithm (.toUpperCase (name alg))]
    (-> (merge {:alg algorithm :typ "JWS"} extra)
        (json/generate-string)
        (codecs/str->bytes)
        (codecs/bytes->safebase64))))

(defn- encode-claims
  "Encode jws claims."
  [input exp nbf iat]
  (-> (normalize-nil-claims {:exp exp :nbf nbf :iat iat})
      (normalize-date-claims)
      (merge input)
      (json/generate-string)
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- parse-header
  "Parse jws header."
  [^String headerdata]
  (-> headerdata
      (codecs/safebase64->bytes)
      (codecs/bytes->str)
      (json/parse-string true)))

(defn- parse-claims
  "Parse jws claims"
  [^String claimsdata]
  (-> claimsdata
      (codecs/safebase64->bytes)
      (codecs/bytes->str)
      (json/parse-string true)))

(defn- parse-algorithm
  "Parse algorithm name and return a
  internal keyword representation of it."
  [header]
  (let [algname (:alg header)]
    (keyword (.toLowerCase algname))))

(defn- get-verifier-for-algorithm
  "Get verifier function for algorithm name."
  [^Keyword alg]
  (when (contains? *signers-map* alg)
    (get-in *signers-map* [alg :verifier])))

(defn- get-signer-for-algorithm
  "Get signer function for algorithm name."
  [^Keyword alg]
  (when (contains? *signers-map* alg)
    (get-in *signers-map* [alg :signer])))

(defn- safe-encode
  "Properly encode string into
  safe url base64 encoding."
  [^String input]
  (-> input
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- calculate-signature
  "Make a jws signature."
  [pkey alg header claims]
  (let [candidate (str/join "." [header claims])
        signer    (get-signer-for-algorithm alg)]
    (-> (signer candidate pkey)
        (codecs/bytes->safebase64))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encode
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [claims pkey & [{:keys [alg exp nbf iat headers] :or {alg :hs256 headers {}}}]]
  {:pre [(map? claims)]}
  (let [header (encode-header alg headers)
        claims (encode-claims claims exp nbf iat)
        signature (calculate-signature pkey alg header claims)]
    (either/right (str/join "." [header claims signature]))))

(defn decode
  "Given a signed message, verify it and return
  the decoded claims.

  This function returns a monadic either instance,
  and if some error is happens in process of decoding
  and verification, it will be reported in an
  either/left instance."
  [input pkey & [{:keys [max-age] :as opts}]]
  {:pre [(string? input)]}
  (let [[header claims signature] (str/split input #"\." 3)
        candidate (str/join "." [header claims])
        header (parse-header header)
        claims (parse-claims claims)
        algorithm (parse-algorithm header)
        signature (codecs/safebase64->bytes signature)
        verifier (get-verifier-for-algorithm algorithm)
        result (verifier candidate signature pkey)]
    (if (false? result)
      (either/left "Invalid token.")
      (let [now (to-timestamp (jodat/now))]
        (cond
          (and (:exp claims) (> now (:exp claims)))
          (either/left (format "Token is older than :exp (%s)" (:exp claims)))

          (and (:nbf claims) (> now (:nbf claims)))
          (either/left (format "Token is older than :nbf (%s)" (:nbf claims)))

          (and (:iat claims) (number? max-age) (< (- now (:iat claims)) max-age))
          (either/left (format "Token is older than :iat (%s)" (:iat claims)))

          :else
          (either/right claims))))))

(defn sign
  "Not monadic version of encode."
  [& args]
  (either/from-either (apply encode args)))

(defn unsign
  "Not monadic version of decode."
  [& args]
  (let [result (apply decode args)]
    (when (either/right? result)
      result)))
