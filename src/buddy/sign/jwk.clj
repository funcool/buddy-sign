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
;; https://tools.ietf.org/html/rfc7517

(ns buddy.sign.jwk
  (:require [cheshire.core :as json]
            [byte-streams :as streams]
            [clojure.core.cache :as cache]
            [aleph.http :as http]
            [buddy.core.keys :as keys]
            [clojure.string :as string]))


(defn- string->edn
  "Parse JSON from a string returning an edn map, otherwise nil"
  [string]
  (when-let [edn (json/decode string true)]
    (when (map? edn)
      edn)))

(defn- fetch
  "Obtain HTTP resource and parse it into a Clojure map"
  [endpoint]
  (-> @(http/get endpoint)
      :body
      streams/to-string
      string->edn))

(def ^:private one-day
  (* 1000                                                   ;milliseconds -> seconds
     60                                                     ;seconds -> minutes
     60                                                     ;mins -> hours
     24))

;; It is not necessary or efficient to obtain these discovery docs on every verification
;; Compose the behaviour of these two caches to limit the number of and length of time
;; that certs that can be held in the cache
(def ^:private jwk-cache (atom (-> {}
                                   (cache/fifo-cache-factory)
                                   (cache/ttl-cache-factory :ttl one-day))))

(defn- fetch-jwk
  "Obtain the JWKs based on the issuer's .well-known URL, cache the result"
  [well-known-endpoint]
  (if (cache/has? @jwk-cache well-known-endpoint)
    (get (cache/hit @jwk-cache well-known-endpoint) well-known-endpoint)
    (when-let [discovery-doc (fetch well-known-endpoint)]
      (let [updated-cache (swap! jwk-cache #(cache/miss % well-known-endpoint discovery-doc))]
        (get updated-cache well-known-endpoint)))))

(defn- cert->pem
  [cert]
  (keys/str->public-key
    (str "-----BEGIN CERTIFICATE-----\n"
         (string/join "\n" (string/join "\n" (re-seq #".{1,64}" cert)))
         "\n-----END CERTIFICATE-----\n")))

(defn get-public-key
  "Obtain the JWK public key from the well-known endpoint that matches the kid"
  [well-known-endpoint kid]
  (when-let [jwks-doc (fetch-jwk well-known-endpoint)]
    (when-let [signing-key (first (filter #(= kid (:kid %)) (:keys jwks-doc)))]
      (cert->pem (first (:x5c signing-key))))))

;Sample usage
;
;(when-let [jwt-header (jws/decode-header jwt)]
;  (when-let [public-key (jwk/get-public-key jwks-endpoint (:kid jwt-header))]
;    (when-let [jwt-claims (jwt/unsign jwt public-key {:alg (:alg jwt-header)})]
;      ....
