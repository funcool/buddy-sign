;; Copyright 2014-2017 Andrey Antukh <niwi@niwi.nz>
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

  "Checks the issuer in the `:iss` claim against one of the allowed issuers in the passed `:iss`. Passed `:iss` may be a string or a vector of strings.
  If no `:iss` is passed, this check is not performed.

  Checks one or more audiences in the `:aud` claim against the single valid audience in the passed `:aud`.
  If no `:aud` is passed, this check is not performed.

  Checks the `:exp` claim is not less than the passed `:now`, with a leeway of the passed `:leeway`.
  If no `:exp` claim exists, this check is not performed.

  Checks the `:nbf` claim is less than the passed `:now`, with a leeway of the passed `:leeway`.
  If no `:nbf` claim exists, this check is not performed.

  Checks the passed `:now` is greater than the `:iat` claim plus the passed `:max-age`. If no `:iat` claim exists, this check is not performed.

  A check that fails raises an exception with `:type` of `:validation` and `:cause` indicating which check failed.

  `:now` is an integer POSIX time and defaults to the current time.
  `:leeway` is an integer number of seconds and defaults to zero."
  [claims {:keys [max-age iss aud now leeway]
           :or {now (util/now) leeway 0}}]
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
     (jws/sign payload pkey opts))))

(defn unsign
  ([message pkey] (unsign message pkey {}))
  ([message pkey {:keys [skip-validation validation-fn] :or {skip-validation false validation-fn validate-claims} :as opts}]
   (try
     (let [claims (-> (jws/unsign message pkey opts)
                      (codecs/bytes->str)
                      (json/parse-string true))]
       (if skip-validation
         claims
         (validation-fn claims (dissoc opts :validation-fn))))
     (catch com.fasterxml.jackson.core.JsonParseException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature}))))))

(defn encrypt
  ([claims pkey] (encrypt claims pkey nil))
  ([claims pkey opts]
   {:pre [(map? claims)]}
   (let [payload (-> (prepare-claims claims opts)
                     (json/generate-string))]
     (jwe/encrypt payload pkey opts))))

(defn decrypt
  ([message pkey] (decrypt message pkey nil))
  ([message pkey {:keys [skip-validation] :or {skip-validation false} :as opts}]
   (try
     (let [claims (-> (jwe/decrypt message pkey opts)
                      (codecs/bytes->str)
                      (json/parse-string true))]
       (if skip-validation
         claims
         (validate-claims claims opts)))
     (catch com.fasterxml.jackson.core.JsonParseException e
       (throw (ex-info "Message seems corrupt or manipulated."
                       {:type :validation :cause :signature}))))))
