;; Copyright (c) 2014-2015 Andrey Antukh <niwi@niwi.be>
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
            [buddy.sign.util :as util]
            [clojure.string :as str]
            [cheshire.core :as json]
            [cats.monad.exception :as exc]
            [slingshot.slingshot :refer [throw+]])

  (:import clojure.lang.Keyword))

(def ^{:doc "List of supported signing algorithms"
       :dynamic true}
  *signers-map* {:hs256 {:signer   #(hmac/hash %1 %2 :sha256)
                         :verifier #(hmac/verify %1 %2 %3 :sha256)}
                 :hs512 {:signer   #(hmac/hash %1 %2 :sha512)
                         :verifier #(hmac/verify %1 %2 %3 :sha512)}
                 :rs256 {:signer   #(rsapkcs/sign %1 %2 :sha256)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha256)}
                 :rs512 {:signer   #(rsapkcs/sign %1 %2 :sha512)
                         :verifier #(rsapkcs/verify %1 %2 %3 :sha512)}
                 :ps256 {:signer   #(rsapss/sign %1 %2 :sha256)
                         :verifier #(rsapss/verify %1 %2 %3 :sha256)}
                 :ps512 {:signer   #(rsapss/sign %1 %2 :sha512)
                         :verifier #(rsapss/verify %1 %2 %3 :sha512)}
                 :es256 {:signer   #(ecdsa/sign %1 %2 :sha256)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha256)}
                 :es512 {:signer   #(ecdsa/sign %1 %2 :sha512)
                         :verifier #(ecdsa/verify %1 %2 %3 :sha512)}})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details
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

(defn encode-header
  "Encode jws header"
  [alg extra]
  (let [algorithm (.toUpperCase (name alg))]
    (-> (merge {:alg algorithm :typ "JWS"} extra)
        (json/generate-string)
        (codecs/str->bytes)
        (codecs/bytes->safebase64))))

(defn encode-claims
  "Encode jws claims."
  [input exp nbf iat]
  (let [additionalclaims (-> (normalize-nil-claims {:exp exp :nbf nbf :iat iat})
                             (normalize-date-claims))]
    (-> (normalize-date-claims input)
        (merge additionalclaims)
        (json/generate-string)
        (codecs/str->bytes)
        (codecs/bytes->safebase64))))

(defn parse-header
  "Parse jws header."
  [^String header]
  (let [header (codecs/safebase64->str header)
        {:keys [alg] :as header} (json/parse-string header true)]
    (when (nil? alg)
      (throw+ {:type :parse :cause :header :message "Missing `alg` key in header."}))
    (merge {:alg (keyword (str/lower-case alg))}
           (dissoc header :alg))))

(defn parse-claims
  "Parse jws claims"
  [^String claimsdata]
  (-> claimsdata
      (codecs/safebase64->bytes)
      (codecs/bytes->str)
      (json/parse-string true)))

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
  ;; [^bytes input ^bytes signature ^bytes key ^Keyword alg]
  [{:keys [alg signature key header claims]}]
  (let [verifier (get-in *signers-map* [alg :verifier])
        authdata (str/join "." [header claims])]
   (verifier authdata signature key)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encode
  "Sign arbitrary length string/byte array using
  json web token/signature."
  [claims pkey & [{:keys [alg exp nbf iat headers] :or {alg :hs256 headers {}}}]]
  {:pre [(map? claims)]}
  (exc/try-on
   (let [header (encode-header alg headers)
         claims (encode-claims claims exp nbf iat)
         signature (calculate-signature {:key pkey
                                         :alg alg
                                         :header header
                                         :claims claims})]
     (str/join "." [header claims signature]))))

(defn decode
  "Given a signed message, verify it and return
  the decoded claims.

  This function returns a monadic either instance,
  and if some error is happens in process of decoding
  and verification, it will be reported in an
  either/left instance."
  [input pkey & [{:keys [max-age] :as opts}]]
  (exc/try-on
   (let [[header claims signature] (str/split input #"\." 3)
         {:keys [alg]} (parse-header header)
         signature (codecs/safebase64->bytes signature)]
     (when-not (verify-signature {:key pkey :signature signature
                                  :alg alg :header header :claims claims})
       (throw+ {:type :validation :cause :auth :message "Message seems corrupt or manipulated."}))
     (let [claims (parse-claims claims)
           now (util/timestamp)]
       (cond
         (and (:exp claims) (> now (:exp claims)))
         (throw+ {:type :validation
                  :cause :exp
                  :message (format "Token is older than :exp (%s)" (:exp claims))})

         (and (:nbf claims) (> now (:nbf claims)))
         (throw+ {:type :validation
                  :cause :nbf
                  :message (format "Token is older than :nbf (%s)" (:nbf claims))})

         (and (:iat claims) (number? max-age) (> (- now (:iat claims)) max-age))
         (throw+ {:type :validation
                  :cause :max-age
                  :message (format "Token is older than max-age (%s)" max-age)})

         :else claims)))))

(defn sign
  "Not monadic version of encode."
  [& args]
  (deref (apply encode args)))

(defn unsign
  "Not monadic version of decode."
  [& args]
  (deref (apply decode args)))
