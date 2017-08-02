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

(ns buddy.sign.jwt
  (:require [buddy.core.codecs :as codecs]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwe :as jwe]
            [buddy.sign.util :as util]
            [cheshire.core :as json]))

(defn- validate-claims
  [claims {:keys [max-age iss aud now leeway] :or {now (util/now) leeway 0}}]
  (let [now (util/to-timestamp now)]

    ;; Check the `:iss` claim.
    (when (and iss (let [iss-claim (:iss claims)]
                     (if (coll? iss)
                       (not-any? #{iss-claim} iss)
                       (not= iss-claim iss))))
      (throw (ex-info (str "Issuer does not match " iss)
                      {:type :validation :cause :iss})))

    ;; Check the `:aud` claim.
    (when (and aud (let [aud-claim (:aud claims)]
                     (if (coll? aud-claim)
                       (not-any? #{aud} aud-claim)
                       (not= aud aud-claim))))
      (throw (ex-info (str "Audience does not match " aud)
                      {:type :validation :cause :aud})))

    ;; Check the `:exp` claim.
    (when (and (:exp claims) (<= (:exp claims) (- now leeway)))
      (throw (ex-info (format "Token is expired (%s)" (:exp claims))
                      {:type :validation :cause :exp})))

    ;; Check the `:nbf` claim.
    (when (and (:nbf claims) (> (:nbf claims) (+ now leeway)))
      (throw (ex-info (format "Token is not yet valid (%s)" (:nbf claims))
                      {:type :validation :cause :nbf})))

    ;; Check the `:max-age` option.
    (when (and (:iat claims) (number? max-age) (> (- now (:iat claims)) max-age))
      (throw (ex-info (format "Token is older than max-age (%s)" max-age)
                      {:type :validation :cause :max-age})))
    claims))

(defn- normalize-date-claims
  "Normalize date related claims and return transformed object."
  [data]
  (into {} (map (fn [[key val]]
                  (if (satisfies? util/ITimestamp val)
                    [key (util/to-timestamp val)]
                    [key val])) data)))

(defn- normalize-nil-claims
  "Given a raw headers, try normalize it removing any
  key with null values."
  [data]
  (into {} (remove (comp nil? second) data)))

(defn- prepare-claims [claims opts]
  (let [additionalclaims (-> (select-keys opts [:exp :nbf :iat :iss :aud])
                             (normalize-nil-claims)
                             (normalize-date-claims))]
    (-> (normalize-date-claims claims)
        (merge additionalclaims))))

(defn sign
  ([claims pkey] (sign claims pkey {}))
  ([claims pkey opts]
   {:pre [(map? claims)]}
   (let [payload (-> (prepare-claims claims opts)
                     (json/generate-string))]
     (jws/sign payload pkey (merge opts {:typ "JWT"})))))

(defn unsign
  ([message pkey] (unsign message pkey {}))
  ([message pkey opts]
   (try
     (-> (jws/unsign message pkey opts)
         (codecs/bytes->str)
         (json/parse-string true)
         (validate-claims opts))
     (catch com.fasterxml.jackson.core.JsonParseException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature}))))))

(defn encrypt
  ([claims pkey] (encrypt claims pkey nil))
  ([claims pkey opts]
   {:pre [(map? claims)]}
   (let [payload (-> (prepare-claims claims opts)
                     (json/generate-string))]
     (jwe/encrypt payload pkey (merge opts {:typ "JWT"})))))

(defn decrypt
  ([message pkey] (decrypt message pkey nil))
  ([message pkey opts]
   (try
     (-> (jwe/decrypt message pkey opts)
         (codecs/bytes->str)
         (json/parse-string true)
         (validate-claims opts))
     (catch com.fasterxml.jackson.core.JsonParseException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature}))))))
